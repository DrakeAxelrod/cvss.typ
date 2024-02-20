

#let test-string = "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:L/MSI:L/MSA:L/S:N/AU:N/R:A/V:D/RE:L/U:Clear"

// Attack Vector (AV):
// Attack Complexity (AC):
// Attack Requirements (AT):
// Privileges Required (PR):
// User Interaction (UI):
// Vulnerable System Impact Metrics
// Confidentiality (VC):
// Integrity (VI):
// Availability (VA):
// Subsequent System Impact Metrics
// Confidentiality (SC):
// Integrity (SI):
// Availability (SA):
// Supplemental Metrics ?
// Safety (S):
// Automatable (AU):
// Recovery (R):
// Value Density (V):
// Vulnerability Response Effort (RE):
// Provider Urgency (U):
// Environmental (Modified Base Metrics) ?
// Exploitability Metrics
// Attack Vector (MAV):
// Attack Complexity (MAC):
// Attack Requirements (MAT):
// Privileges Required (MPR):
// User Interaction (MUI):
// Vulnerable System Impact Metrics
// Confidentiality (MVC):
// Integrity (MVI):
// Availability (MVA):
// Subsequent System Impact Metrics
// Confidentiality (MSC):
// Integrity (MSI):
// Availability (MSA):
// Environmental (Security Requirements) ?
// Confidentiality Requirements (CR):
// Integrity Requirements (IR):
// Availability Requirements (AR):
// Threat Metrics ?
// Exploit Maturity (E):


#let header = "CVSS\:4\.0"
// #let metric = "[\/]([A-Z]{1,3})\:"

#let re-metric(key, vals) = {
  "[/]?(" + key +  ":[" + vals + "])?"
}

// #let verify(s) = {
//   let re = regex("CVSS\:4\.0"
//           // Base Metrics
//           + re-metric("AV", "N|A|L|P|Network|Adjacent|Local|Physical")
//           + re-metric("AC", "H|L|High|Low")
//           + re-metric("AT", "N|P|None|Present")
//           + re-metric("PR", "N|L|H|None|Low|High")
//           + re-metric("UI", "N|R|A|None|Required|All")
//           // Vulnerable System Impact Metrics
//           + re-metric("VC", "N|L|H|None|Low|High")
//           + re-metric("VI", "N|L|H|None|Low|High")
//           + re-metric("VA", "N|L|H|None|Low|High")
//           // Subsequent System Impact Metrics
//           + re-metric("SC", "N|L|H|None|Low|High")
//           + re-metric("SI", "N|L|H|None|Low|High")
//           + re-metric("SA", "N|L|H|None|Low|High")
//   )
//   s.matches(re)
// }

// #verify(test-string)

#let re = regex("CVSS:4.0([/?[A-Za-z]{1,3}:[A-Za-z]]+)")

// #let res = test-string.match(regex("CVSS:4.0([/?[A-Za-z]{1,3}:[A-Za-z]]+)"))

// #res.captures.at(0).split("/").fold((:), (acc, x) => {
//   if x == "" { return acc }
//   let kv = x.split(":")
//   acc + ((kv.at(0)): kv.at(1))
// })

#let metrics(s) = {
  let re = regex("CVSS:4.0([/?[A-Za-z]{1,3}:[A-Za-z]]+)")
  let res = s.match(re)
  res.captures.at(0).split("/").fold((:), (acc, x) => {
    if x == "" { return acc }
    let kv = x.split(":")
    acc + ((kv.at(0)): kv.at(1))
  })
}

#metrics(test-string)
