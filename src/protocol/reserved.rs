bitflags::bitflags! {
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
    pub struct Reserved: u8 {
        const NONE       = 0b0000_0000;
    }
}
