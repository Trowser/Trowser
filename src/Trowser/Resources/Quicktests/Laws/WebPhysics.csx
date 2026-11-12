// @title Web physics
// @shadow light
// @effects none
// @see Reliability/ConsoleAndNetworkErrors.csx

Law("Document has a title")
    .OnPage("*")
    .Expect((PageFacts p) => !string.IsNullOrWhiteSpace(p.Title))
    .Severity(Severity.Low)
    .Tags("generic");
