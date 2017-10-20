pub mod records;

use asn1::*;
use self::records::*;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Cdr {
    pub seq: Vec<Record>,
}

named!(cdr<Cdr>,
    do_parse!(
        _header: tlv!(0xA0 => ignore)
    >>  sequence: tlv!(0xA1 => sequence!(record))
    >>  _trailer: tlv!(0xA2 => ignore)
    >>  _extensions: tlv!(0xA3 => ignore)
    >>  (Cdr { seq: sequence })
    )
);

named!(pub parse<Cdr>, terminated!(tlv!(0x30 => cdr), eof!()));
