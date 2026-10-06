import SwiftUI
import Combine
import AppKit
import UniformTypeIdentifiers

// MARK: - JX-8P patch handling

enum JX8P {
    /// A single JX-8P patch message: F0 41 35 0n 21 20 01 <10 name bytes> <49 param bytes> F7
    static let patchLength = 67
    static let nameRange = 7..<17

    /// Returns nil if the bytes look like a valid JX-8P patch, otherwise a reason it was rejected.
    static func validate(_ bytes: [UInt8]) -> String? {
        guard bytes.first == 0xF0, bytes.last == 0xF7 else {
            return "It isn't a single complete SysEx message (missing F0 or F7)."
        }
        guard bytes.count == patchLength else {
            return "Expected \(patchLength) bytes for a JX-8P patch, but the file has \(bytes.count)."
        }
        guard bytes[1] == 0x41 else { return "Not a Roland SysEx message." }
        guard bytes[2] == 0x35 else { return "Not a patch (All Parameters) dump." }
        guard bytes[4] == 0x21 else { return "Not a JX-8P message (model byte is not 0x21)." }
        guard bytes[5] == 0x20 else {
            return "Not single-tone data (it may be a JX-10/MKS-70 patch, which holds two tones)."
        }
        guard bytes[1..<(bytes.count - 1)].allSatisfy({ $0 < 0x80 }) else {
            return "Contains invalid data bytes."
        }
        return nil
    }

    struct ConversionError: Error { let message: String }

    /// Turns a tone message into a standard JX-8P patch message (67 bytes).
    ///  • JX-8P patch:              F0 41 35 0n 21 20 01 <59 bytes> F7            (used as is)
    ///  • JX-10/MKS-70 "APR" tone:  F0 41 35 0n 24 20 0g <59 bytes> F7            (model byte changed)
    ///  • JX-10/MKS-70 "BLD" tone:  F0 41 37 0n 24 20 0g 00 <tone#> <59 bytes> F7 (header rebuilt)
    /// The 59 bytes are the 10-character name plus 49 parameters, which are the same on all these synths.
    /// `converted` is true when the message came from a JX-10/MKS-70 format.
    static func normalize(_ m: [UInt8]) throws -> (patch: [UInt8], converted: Bool) {
        guard m.count > 8, m[0] == 0xF0, m[1] == 0x41, m.last == 0xF7 else {
            throw ConversionError(message: "It isn't a complete Roland SysEx message.")
        }
        let opcode = m[2], model = m[4], level = m[5]
        var patch: [UInt8]
        var converted = true

        switch opcode {
        case 0x35 where model == 0x21 || model == 0x24:
            patch = m
            converted = (model != 0x21)
        case 0x37 where model == 0x24:
            guard level == 0x20 else {
                throw ConversionError(message:
                    "This is a JX-10/MKS-70 patch (a two-tone performance), not a single tone, so it can't go in a JX-8P bank.")
            }
            guard m.count == 69, m[7] == 0x00 else {
                throw ConversionError(message:
                    "Unexpected JX-10/MKS-70 tone dump length (\(m.count) bytes; expected 69).")
            }
            // Skip the two extra bytes (00, tone number) and keep name + 49 parameters.
            patch = [0xF0, 0x41, 0x35, 0x00, 0x21, 0x20, 0x01] + Array(m[9..<(m.count - 1)]) + [0xF7]
        default:
            throw ConversionError(message: "Not a tone/patch message this app understands.")
        }

        // Normalise the header to match a real JX-8P dump.
        patch[3] = 0x00
        patch[4] = 0x21
        if patch.count > 6 { patch[6] = 0x01 }

        if let reason = validate(patch) { throw ConversionError(message: reason) }
        return (patch, converted)
    }

    /// Splits a raw .syx byte stream into individual F0…F7 messages.
    static func splitMessages(_ bytes: [UInt8]) -> [[UInt8]] {
        var result: [[UInt8]] = []
        var start: Int?
        for (i, b) in bytes.enumerated() {
            if b == 0xF0 {
                start = i
            } else if b == 0xF7, let s = start {
                result.append(Array(bytes[s...i]))
                start = nil
            }
        }
        return result
    }

    /// The 11-byte "Program Number" message the JX-8P writes after each patch in a bank dump.
    /// It tells the synth which of the 32 memory slots (0–31) the preceding patch belongs in.
    static func slotMessage(for slot: Int) -> [UInt8] {
        [0xF0, 0x41, 0x34, 0x00, 0x21, 0x20, 0x01, 0x00, UInt8(slot), 0x02, 0xF7]
    }

    static func patchName(_ bytes: [UInt8]) -> String {
        let chars: [Character] = bytes[nameRange].map {
            ($0 >= 32 && $0 < 127) ? Character(UnicodeScalar($0)) : " "
        }
        return String(chars).trimmingCharacters(in: .whitespaces)
    }
}

// MARK: - Model

struct Slot: Identifiable {
    let id: Int
    var fileName: String?
    var patchName: String?
    var data: Data?
    var converted = false
}

@MainActor
final class BankModel: ObservableObject {
    @Published var slots: [Slot] = (0..<32).map { Slot(id: $0) }
    @Published var alertMessage: String?

    var filledCount: Int { slots.filter { $0.data != nil }.count }
    var isComplete: Bool { filledCount == slots.count }

    /// Loads one or more files, filling consecutive slots starting at `index`.
    /// A file can be a single patch or a whole bank dump; the slot-assignment
    /// messages in a bank are ignored, and patches are placed in order.
    func load(urls: [URL], startingAt index: Int) {
        var problems: [String] = []
        var target = index

        for url in urls {
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }

            do {
                let bytes = [UInt8](try Data(contentsOf: url))
                // Candidate tone messages: JX-8P / JX-10 "APR" (0x35) and JX-10/MKS-70 "BLD" (0x37).
                // Other messages, such as the 0x34 slot-number messages in a bank, are ignored.
                let candidates = JX8P.splitMessages(bytes).filter {
                    $0.count > 3 && ($0[2] == 0x35 || $0[2] == 0x37)
                }
                if candidates.isEmpty {
                    problems.append("\(url.lastPathComponent): no JX-8P or JX-10/MKS-70 tone found.")
                    continue
                }
                for message in candidates {
                    guard target < slots.count else {
                        let text = "\(url.lastPathComponent): ran out of slots (only 0–31)."
                        if !problems.contains(text) { problems.append(text) }
                        break
                    }
                    do {
                        let result = try JX8P.normalize(message)
                        slots[target] = Slot(id: target,
                                             fileName: url.lastPathComponent,
                                             patchName: JX8P.patchName(result.patch),
                                             data: Data(result.patch),
                                             converted: result.converted)
                        target += 1
                    } catch let error as JX8P.ConversionError {
                        let text = "\(url.lastPathComponent): \(error.message)"
                        if !problems.contains(text) { problems.append(text) }
                    }
                }
            } catch {
                problems.append("\(url.lastPathComponent): \(error.localizedDescription)")
            }
        }
        if !problems.isEmpty {
            alertMessage = problems.joined(separator: "\n")
        }
    }

    func clear(_ index: Int) { slots[index] = Slot(id: index) }
    func clearAll() { slots = (0..<32).map { Slot(id: $0) } }

    func export() {
        guard isComplete else { return }

        let panel = NSSavePanel()
        panel.title = "Save JX-8P Bank"
        panel.allowedContentTypes = [UTType(filenameExtension: "syx") ?? .data]
        panel.nameFieldStringValue = "JX-8P Bank.syx"
        panel.canCreateDirectories = true

        guard panel.runModal() == .OK, let url = panel.url else { return }

        // Same layout as a real JX-8P bank dump: for each slot, the 67-byte patch
        // message followed by the 11-byte slot-number message (78 bytes × 32 = 2496).
        var out = Data()
        for (i, slot) in slots.enumerated() {
            guard let patch = slot.data else { return }
            out.append(patch)
            out.append(contentsOf: JX8P.slotMessage(for: i))
        }

        do {
            try out.write(to: url, options: .atomic)
            alertMessage = "Saved \(out.count) bytes (32 patches) to \(url.lastPathComponent)."
        } catch {
            alertMessage = "Couldn't save the bank: \(error.localizedDescription)"
        }
    }
}

// MARK: - Views

struct SlotView: View {
    let slot: Slot
    let onDrop: ([URL]) -> Void
    let onClear: () -> Void
    @State private var targeted = false

    var body: some View {
        let filled = slot.data != nil

        VStack(spacing: 4) {
            Text("\(slot.id)")
                .font(.system(.headline, design: .monospaced))
            Text(slot.patchName.flatMap { $0.isEmpty ? nil : $0 } ?? (filled ? "(unnamed)" : "Drop patch"))
                .font(.caption)
                .lineLimit(1)
                .foregroundStyle(.secondary)
            if slot.converted {
                Text("from JX-10")
                    .font(.system(size: 9))
                    .foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 64)
        .padding(6)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(filled ? Color.green.opacity(0.18) : Color.secondary.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(targeted ? Color.accentColor : Color.secondary.opacity(0.4),
                              style: StrokeStyle(lineWidth: targeted ? 3 : 1,
                                                 dash: filled ? [] : [5]))
        )
        .overlay(alignment: .topTrailing) {
            if filled {
                Button(action: onClear) {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .padding(4)
                .help(slot.fileName ?? "Clear slot")
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            onDrop(urls)
            return true
        } isTargeted: { targeted = $0 }
    }
}

struct ContentView: View {
    @StateObject private var model = BankModel()
    private let columns = Array(repeating: GridItem(.flexible(), spacing: 10), count: 8)

    var body: some View {
        VStack(spacing: 16) {
            Text("JX-8P Bank Builder")
                .font(.title2.bold())

            Text("Drag a JX-8P .syx patch, or JX-10/MKS-70 .syx, onto any slot. Dropping several files, or a whole bank, fills consecutive slots.")
                .font(.callout)
                .foregroundStyle(.secondary)

            LazyVGrid(columns: columns, spacing: 10) {
                ForEach(model.slots) { slot in
                    SlotView(slot: slot,
                             onDrop: { urls in model.load(urls: urls, startingAt: slot.id) },
                             onClear: { model.clear(slot.id) })
                }
            }

            HStack {
                Text("\(model.filledCount) / 32 slots filled")
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Clear All") { model.clearAll() }
                    .disabled(model.filledCount == 0)
                Button("Export Bank…") { model.export() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.isComplete)
            }
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 420)
        .alert("JX-8P Bank Builder",
               isPresented: Binding(get: { model.alertMessage != nil },
                                    set: { if !$0 { model.alertMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.alertMessage ?? "")
        }
    }
}

#Preview {
    ContentView()
}
