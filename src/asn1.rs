use nom::be_u8;

named!(pub length<u32>,
    switch!(bits!(pair!(take_bits!(u8, 1), take_bits!(usize, 7))),
        (0, n) => value!(n as u32) |
        (1, n @ 1...4) => fold_many_m_n!(n, n, be_u8, 0, |acc: u32, i| { acc * 0x100 + (i as u32)})
    )
);

macro_rules! tlv {
    ( $i:expr , $($tag:expr),+ => $submac:ident!( $($args:tt)* ) ) => {
        complete!($i,
            do_parse!(
                tag!([$($tag),+])
            >>  res: length_value!(length, $submac!($($args)*))
            >>  (res)
            )
        )
    };
    ( $i:expr , $($tag:expr),+ => $parser:expr ) => {
        tlv!($i, $($tag),+ => call!($parser))
    };
}

macro_rules! sequence {
    ( $i:expr , $submac:ident!( $($args:tt)* ) ) => {
        terminated!($i, many0!($submac!($($args)*)), eof!())
    };
    ( $i:expr , $parser:expr ) => {
        sequence!($i, call!($parser))
    };
}

named!(pub ignore<()>, value!(()));
