use solana_program::pubkey::Pubkey;

pub mod spl_token {
    use super::*;
    
    pub fn id() -> Pubkey {
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            .parse()
            .unwrap()
    }
} 