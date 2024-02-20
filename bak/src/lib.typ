
#let severity = (
  NONE: "None",
  LOW: "Low",
  MEDIUM: "Medium",
  HIGH: "High",
  CRITICAL: "Critical"
)



#let test-string = "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:L/IR:L/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:L/MSI:L/MSA:L/S:N/AU:N/R:A/V:D/RE:L/U:Clear"

#let re = regex("([A-Za-z]{1,3}):([A-Za-z]{1,11})")

#let metrics(s) = {
  s.matches(re).fold((:), (acc, it) => {
    let (k, v) = it.captures
    acc + ((k): v)
  })
}


// None 	0.0
// Low 	0.1 - 3.9
// Medium 	4.0 - 6.9
// High 	7.0 - 8.9
// Critical 	9.0 - 10.0
#let severity(s) = {
  
}

#metrics(test-string)
