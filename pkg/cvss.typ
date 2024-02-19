#let _cvss = plugin("cvss.wasm")


#str(_cvss.cvss(bytes("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")))

#str(_cvss.cvss(bytes("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")))

#str(_cvss.cvss(bytes("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H")))

#str(_cvss.cvss(bytes("CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")))


// #let cvss = (
//   vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
//   calc: (v) => float(str(_cvss.cvss(bytes(v)))),
// )

// #(cvss.calc)("CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")

#let cvss40 = (
  re: {
    let header = "CVSS\:4\.0"
    let av = "[\/]?(AV\:[N|A|L|P])?"
    let ac = "[\/]?(AC\:[L|H])"
    let at = "[\/]?(AT\:[N|P])?"
    let pr = "[\/]?(PR\:[N|L|H])?"
    let ui = "[\/]?(UI\:[N|R|A])?"
    // Vulnerable System Impact Metrics
    let vc = "[\/]?(VC\:[N|L|H])?"
    let vi = "[\/]?(VI\:[N|L|H])?"
    let va = "[\/]?(VA\:[N|L|H])?"
    // Subsequent System Impact Metrics
    let sc = "[\/]?(SC\:[N|L|H])?"
    let si = "[\/]?(SI\:[N|L|H])?"
    let sa = "[\/]?(SA\:[N|L|H])?"
    // Supplemental Metrics
    let s = "[\/]?(S\:[X|N|P])?"
    let au = "[\/]?(AU\:[X|N|Y])?"
    let r = "[\/]?(R\:[X|A|U|I])?"
    let v = "[\/]?(V\:[X|D|C])?"
    let re = "[\/]?(V\:[X|L|M|H])?"
    let u = "[\/]?(U\:[X|Clear|Green|Amber|Red])?"
    let metric = "[\/]([A-Z]{1,3})\:"
    // regex("CVSS\:4\.0[\/]?(AV\:[N|A|L|P])?[\/](AC\:[L|H])")
    regex(header + metric)
  }
)
#let cvss31 = (
  re: regex("CVSS:3.1/AV:(N|A|L|P)/AC:(L|H)/PR:(N|L|H)/UI:(N|R|A)/S:(U|C)/C:(N|L|H)/I:(N|L|H)/A:(N|L|H)"),
)
#let cvss30 = (
  re: regex("CVSS:3.0/AV:(N|A|L|P)/AC:(L|H)/PR:(N|L|H)/UI:(N|R|A)/S:(U|C)/C:(N|L|H)/I:(N|L|H)/A:(N|L|H)"),
)
#let cvss20 = (
  re: regex("CVSS:2.0/AV:(N|A|L|P)/AC:(L|H)/Au:(N|S|M)/C:(N|P|C)/I:(N|P|C)/A:(N|P|C)"),
)

#let verify(
  // re,
  vector,
) = {
  // if vector.starts_with("CVSS:4.0") {
  //   let re = cvss40.re;
  //   re.match(vector)
  // }
  vector = upper(vector)
            .replace("CLEAR", "Clear")
            .replace("GREEN", "Green")
            .replace("AMBER", "Amber")
            .replace("RED", "Red")
  if vector.starts-with("CVSS:4.0") {
    let re = cvss40.re;
    vector.matches(re)
  }
}

#verify("CVSS:4.0/AV:None/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
