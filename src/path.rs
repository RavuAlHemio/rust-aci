use std::error::Error;
use std::fmt;

/// An error returned if splitting a Distinguished Name (DN) has been unsuccessful.
#[derive(Debug, PartialEq, Eq)]
pub enum SplitDnError {
    /// At the end of the DN, at least one square bracket remained open.
    UnclosedSquareBrackets(usize),

    /// In the DN, more square brackets were closed than were previously open.
    OverclosedSquareBracket(usize),
}
impl fmt::Display for SplitDnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            SplitDnError::UnclosedSquareBrackets(num) =>
                write!(f, "{} square brackets remained unclosed", num),
            SplitDnError::OverclosedSquareBracket(byte_pos) =>
                write!(
                    f,
                    "more square brackets closed than previously opened at byte position {}",
                    byte_pos,
                ),
        }
    }
}
impl Error for SplitDnError {
}

/// Splits a Distinguished Name (DN) into its component Relative Distinguished Names (RDNs). ACI
/// DNs consist of RDNs joined by forward slash characters, which can be escaped by placing them
/// into square brackets. Square brackets can be nested.
pub fn split_dn(dn: &str) -> Result<Vec<&str>, SplitDnError> {
    let mut start_index = 0usize;
    let mut bracket_depth = 0usize;
    let mut slices: Vec<&str> = Vec::new();

    // string slices address bytes, so iterate string as bytes
    let bs: Vec<u8> = dn.bytes().collect();
    for i in 0..bs.len() {
        if bs[i] == ('[' as u8) {
            bracket_depth += 1;
        } else if bs[i] == (']' as u8) {
            if bracket_depth == 0 {
                return Err(SplitDnError::OverclosedSquareBracket(i));
            }
            bracket_depth -= 1;
        } else if bs[i] == ('/' as u8) && bracket_depth == 0 {
            // this is the split point
            slices.push(&dn[start_index..i]);
            start_index = i + 1;
        }
    }

    // append the last slice
    slices.push(&dn[start_index..]);

    if bracket_depth > 0 {
        Err(SplitDnError::UnclosedSquareBrackets(bracket_depth))
    } else {
        Ok(slices)
    }
}

mod test {
    use super::*;

    #[test]
    fn flat_dn() {
        let slices = split_dn("uni/fabric/leportp-MyLPSelectorProf").unwrap();
        assert_eq!(slices.len(), 3);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "fabric");
        assert_eq!(slices[2], "leportp-MyLPSelectorProf");
    }

    #[test]
    fn flat_dn_with_initial_slash() {
        let slices = split_dn("/uni/fabric/leportp-MyLPSelectorProf").unwrap();
        assert_eq!(slices.len(), 4);
        assert_eq!(slices[0], "");
        assert_eq!(slices[1], "uni");
        assert_eq!(slices[2], "fabric");
        assert_eq!(slices[3], "leportp-MyLPSelectorProf");
    }

    #[test]
    fn flat_dn_with_medial_slash() {
        let slices = split_dn("uni/fabric//leportp-MyLPSelectorProf").unwrap();
        assert_eq!(slices.len(), 4);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "fabric");
        assert_eq!(slices[2], "");
        assert_eq!(slices[3], "leportp-MyLPSelectorProf");
    }

    #[test]
    fn flat_dn_with_final_slash() {
        let slices = split_dn("uni/fabric/leportp-MyLPSelectorProf/").unwrap();
        assert_eq!(slices.len(), 4);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "fabric");
        assert_eq!(slices[2], "leportp-MyLPSelectorProf");
        assert_eq!(slices[3], "");
    }

    #[test]
    fn flat_dn_with_initial_slashes() {
        let slices = split_dn("//uni/fabric/leportp-MyLPSelectorProf").unwrap();
        assert_eq!(slices.len(), 5);
        assert_eq!(slices[0], "");
        assert_eq!(slices[1], "");
        assert_eq!(slices[2], "uni");
        assert_eq!(slices[3], "fabric");
        assert_eq!(slices[4], "leportp-MyLPSelectorProf");
    }

    #[test]
    fn flat_dn_with_medial_slashes() {
        let slices = split_dn("uni/fabric///leportp-MyLPSelectorProf").unwrap();
        assert_eq!(slices.len(), 5);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "fabric");
        assert_eq!(slices[2], "");
        assert_eq!(slices[3], "");
        assert_eq!(slices[4], "leportp-MyLPSelectorProf");
    }

    #[test]
    fn flat_dn_with_final_slashes() {
        let slices = split_dn("uni/fabric/leportp-MyLPSelectorProf//").unwrap();
        assert_eq!(slices.len(), 5);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "fabric");
        assert_eq!(slices[2], "leportp-MyLPSelectorProf");
        assert_eq!(slices[3], "");
        assert_eq!(slices[4], "");
    }

    #[test]
    fn bracketed_dn() {
        let slices = split_dn(
            "uni/fabric/nodecfgcont/node-1001/rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]/fault-F1300"
        ).unwrap();
        assert_eq!(slices.len(), 6);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "fabric");
        assert_eq!(slices[2], "nodecfgcont");
        assert_eq!(slices[3], "node-1001");
        assert_eq!(slices[4], "rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]");
        assert_eq!(slices[5], "fault-F1300");
    }

    #[test]
    fn bracketed_dn_with_initial_slashes() {
        let slices = split_dn(
            "//uni/fabric/nodecfgcont/node-1001/rsnodeGroup-[/uni/fabric/maintgrp-MAINT_GRP_SAMPLE]/fault-F1300"
        ).unwrap();
        assert_eq!(slices.len(), 8);
        assert_eq!(slices[0], "");
        assert_eq!(slices[1], "");
        assert_eq!(slices[2], "uni");
        assert_eq!(slices[3], "fabric");
        assert_eq!(slices[4], "nodecfgcont");
        assert_eq!(slices[5], "node-1001");
        assert_eq!(slices[6], "rsnodeGroup-[/uni/fabric/maintgrp-MAINT_GRP_SAMPLE]");
        assert_eq!(slices[7], "fault-F1300");
    }

    #[test]
    fn bracketed_dn_with_medial_slashes() {
        let slices = split_dn(
            "uni/fabric/nodecfgcont/node-1001/rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]//fault-F1300"
        ).unwrap();
        assert_eq!(slices.len(), 7);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "fabric");
        assert_eq!(slices[2], "nodecfgcont");
        assert_eq!(slices[3], "node-1001");
        assert_eq!(slices[4], "rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]");
        assert_eq!(slices[5], "");
        assert_eq!(slices[6], "fault-F1300");
    }

    #[test]
    fn bracketed_dn_with_final_slashes() {
        let slices = split_dn(
            "uni/fabric/nodecfgcont/node-1001/rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]/fault-F1300//"
        ).unwrap();
        assert_eq!(slices.len(), 8);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "fabric");
        assert_eq!(slices[2], "nodecfgcont");
        assert_eq!(slices[3], "node-1001");
        assert_eq!(slices[4], "rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]");
        assert_eq!(slices[5], "fault-F1300");
        assert_eq!(slices[6], "");
        assert_eq!(slices[7], "");
    }

    #[test]
    fn multibracketed_dn() {
        let slices = split_dn(
            "uni/epp/fv-[uni/tn-TENANT/ap-DESKTOP/epg-DESK020]/node-106/dyatt-[topology/pod-1/\
            paths-106/pathep-[eth1/11]]/conndef/conn-[vlan-1611]-[0.0.0.0]/\
            epdefref-00:50:56:00:00:00/rstoFvPrimaryEncapDef-[uni/epp/fv-[uni/tn-TENANT/ap-DESKTOP/\
            epg-DESK020]/node-106/dyatt-[topology/pod-1/paths-106/pathep-[eth1/11]]/conndef/\
            conn-[vlan-1611]-[0.0.0.0]/primencap-[vlan-1612]]/byDom-[uni/vmmp-VMware/dom-SWAGDVS]/\
            byHv-[comp/prov-VMware/ctrlr-[SWAGDVS]-SWAGDVS/hv-host-83]"
        ).unwrap();
        assert_eq!(slices.len(), 11);
        assert_eq!(slices[0], "uni");
        assert_eq!(slices[1], "epp");
        assert_eq!(slices[2], "fv-[uni/tn-TENANT/ap-DESKTOP/epg-DESK020]");
        assert_eq!(slices[3], "node-106");
        assert_eq!(slices[4], "dyatt-[topology/pod-1/paths-106/pathep-[eth1/11]]");
        assert_eq!(slices[5], "conndef");
        assert_eq!(slices[6], "conn-[vlan-1611]-[0.0.0.0]");
        assert_eq!(slices[7], "epdefref-00:50:56:00:00:00");
        assert_eq!(slices[8], "rstoFvPrimaryEncapDef-[uni/epp/fv-[uni/tn-TENANT/ap-DESKTOP/epg-DESK020]/node-106/dyatt-[topology/pod-1/paths-106/pathep-[eth1/11]]/conndef/conn-[vlan-1611]-[0.0.0.0]/primencap-[vlan-1612]]");
        assert_eq!(slices[9], "byDom-[uni/vmmp-VMware/dom-SWAGDVS]");
        assert_eq!(slices[10], "byHv-[comp/prov-VMware/ctrlr-[SWAGDVS]-SWAGDVS/hv-host-83]");
    }

    #[test]
    fn overclosed_bracket() {
        let err = split_dn(
            "uni/fabric/nodecfgcont/node-1001/rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]]/fault-F1300"
        ).unwrap_err();
        assert_eq!(
            err,
            SplitDnError::OverclosedSquareBracket(
                "uni/fabric/nodecfgcont/node-1001/rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]]".len()-1
            )
        );
    }

    #[test]
    fn unclosed_bracket() {
        let err = split_dn(
            "uni/fabric/nodecfgcont/node-1001/rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE]/fault-[F1300"
        ).unwrap_err();
        assert_eq!(err, SplitDnError::UnclosedSquareBrackets(1));
    }

    #[test]
    fn unclosed_brackets() {
        let err = split_dn(
            "uni/fabric/nodecfgcont/node-1001/rsnodeGroup-[uni/fabric/maintgrp-MAINT_GRP_SAMPLE/fault-[F1300"
        ).unwrap_err();
        assert_eq!(err, SplitDnError::UnclosedSquareBrackets(2));
    }
}
