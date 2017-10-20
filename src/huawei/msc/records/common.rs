use nom::be_u8;

macro_rules! field {
    ( $i:expr , $($tag:expr),+ => $submac:ident!( $($args:tt)* ) => $r:ident.$name:ident) => {
        map!($i, tlv!($($tag),+ => $submac!($($args)*)), |v| { let mut r = $r; r.$name = v; r })
    };
    ( $i:expr , $($tag:expr),+ => $parser:expr => $r:ident.$name:ident) => {
        field!($i, $($tag),+ => call!($parser) => $r.$name)
    };
}

named!(pub address<u64>,
    fold_many0!(be_u8, 0, |acc: u64, i| { acc * 100 + ((i % 16) * 10 + i / 16) as u64 })
);
