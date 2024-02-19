#let _cvss = plugin("cvss.wasm")


#str(_cvss.cvss(bytes("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")))

#str(_cvss.cvss(bytes("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")))

#str(_cvss.cvss(bytes("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H")))

#str(_cvss.cvss(bytes("CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")))
