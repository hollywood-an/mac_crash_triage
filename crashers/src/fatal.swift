// Swift runtime trap (fatalError): EXC_BREAKPOINT / SIGTRAP.

@inline(never)
func requirePositive(_ n: Int) -> Int {
    guard n > 0 else {
        fatalError("expected a positive count")
    }
    return n
}

print(requirePositive(CommandLine.arguments.count - 1))
