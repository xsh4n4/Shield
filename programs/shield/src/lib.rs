use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("DuFBJmHcD2bhw1eE7xYYYramiQmCBzTLSRCi6tpWGTPF");

#[program]
pub mod shield {
    use super::*;

    /// Initialize the Shield protocol configuration
    pub fn initialize(
        ctx: Context<Initialize>,
        lp_share_bps: u16,
        treasury_share_bps: u16,
        user_rebate_bps: u16,
    ) -> Result<()> {
        require!(
            lp_share_bps + treasury_share_bps + user_rebate_bps == 10000,
            ShieldError::InvalidShareDistribution
        );

        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.lp_share_bps = lp_share_bps;
        config.treasury_share_bps = treasury_share_bps;
        config.user_rebate_bps = user_rebate_bps;
        config.lp_rewards_vault = ctx.accounts.lp_rewards_vault.key();
        config.treasury_vault = ctx.accounts.treasury_vault.key();
        config.bump = ctx.bumps.config;

        msg!(
            "Shield initialized with LP: {}%, Treasury: {}%, Rebate: {}%",
            lp_share_bps / 100,
            treasury_share_bps / 100,
            user_rebate_bps / 100
        );

        Ok(())
    }

    /// Submit a swap intent (user -> hidden order)
    pub fn submit_intent(
        ctx: Context<SubmitIntent>,
        token_in: Pubkey,
        token_out: Pubkey,
        amount_in: u64,
        min_amount_out: u64,
        expiry_ts: i64,
    ) -> Result<()> {
        let clock = Clock::get()?;

        require!(
            expiry_ts > clock.unix_timestamp,
            ShieldError::ExpiredIntent
        );
        require!(amount_in > 0, ShieldError::InvalidAmount);
        require!(min_amount_out > 0, ShieldError::InvalidAmount);

        let intent = &mut ctx.accounts.intent;
        intent.user = ctx.accounts.user.key();
        intent.token_in = token_in;
        intent.token_out = token_out;
        intent.amount_in = amount_in;
        intent.min_amount_out = min_amount_out;
        intent.expiry_ts = expiry_ts;
        intent.executed = false;
        intent.executor = Pubkey::default();
        intent.bid_amount = 0;
        intent.bump = 0; // no PDA bump used here
        intent.created_at = clock.unix_timestamp;

        emit!(SwapIntentEvent {
            intent_id: intent.key(),
            user: intent.user,
            token_in: intent.token_in,
            token_out: intent.token_out,
            amount_in: intent.amount_in,
            min_amount_out: intent.min_amount_out,
            expiry_ts: intent.expiry_ts,
            timestamp: clock.unix_timestamp,
        });

        msg!(
            "Intent submitted: {} {} for {} {}",
            amount_in,
            token_in,
            min_amount_out,
            token_out
        );

        Ok(())
    }

    /// Finalize swap execution (called by relayer / auction winner)
    pub fn finalize_swap(
        ctx: Context<FinalizeSwap>,
        bid_amount: u64,
        actual_amount_out: u64,
    ) -> Result<()> {
        let intent = &mut ctx.accounts.intent;
        let clock = Clock::get()?;

        require!(!intent.executed, ShieldError::AlreadyExecuted);
        require!(
            clock.unix_timestamp <= intent.expiry_ts,
            ShieldError::ExpiredIntent
        );
        require!(
            actual_amount_out >= intent.min_amount_out,
            ShieldError::SlippageExceeded
        );
        require!(bid_amount > 0, ShieldError::InvalidBidAmount);

        // Validate token account ownership and mints
        require!(
            ctx.accounts.executor_token_account.owner == ctx.accounts.executor.key(),
            ShieldError::UnauthorizedExecutor
        );
        require!(
            ctx.accounts.user_token_account.owner == intent.user,
            ShieldError::UnauthorizedExecutor
        );
        require!(
            ctx.accounts.revenue_vault.owner == ctx.accounts.config.key(),
            ShieldError::UnauthorizedExecutor
        );
        
        // Validate all token accounts use the same mint
        let bid_mint = ctx.accounts.revenue_vault.mint;
        require!(
            ctx.accounts.executor_token_account.mint == bid_mint,
            ShieldError::InvalidAmount
        );
        require!(
            ctx.accounts.lp_rewards_vault.mint == bid_mint,
            ShieldError::InvalidAmount
        );
        require!(
            ctx.accounts.treasury_vault.mint == bid_mint,
            ShieldError::InvalidAmount
        );
        require!(
            ctx.accounts.user_token_account.mint == bid_mint,
            ShieldError::InvalidAmount
        );

        let executor = ctx.accounts.executor.key();

        intent.executed = true;
        intent.executor = executor;
        intent.bid_amount = bid_amount;

        // Transfer bid from executor -> revenue vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.executor_token_account.to_account_info(),
            to: ctx.accounts.revenue_vault.to_account_info(),
            authority: ctx.accounts.executor.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, bid_amount)?;

        // Calculate splits
        let config = &ctx.accounts.config;
        let lp_amount = (bid_amount as u128 * config.lp_share_bps as u128 / 10000) as u64;
        let treasury_amount =
            (bid_amount as u128 * config.treasury_share_bps as u128 / 10000) as u64;
        let user_rebate =
            (bid_amount as u128 * config.user_rebate_bps as u128 / 10000) as u64;

        let seeds = &[b"config".as_ref(), &[config.bump]];
        let signer = &[&seeds[..]];

        // LP share
        if lp_amount > 0 {
            let cpi_accounts = Transfer {
                from: ctx.accounts.revenue_vault.to_account_info(),
                to: ctx.accounts.lp_rewards_vault.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            };
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                signer,
            );
            token::transfer(cpi_ctx, lp_amount)?;
        }

        // Treasury share
        if treasury_amount > 0 {
            let cpi_accounts = Transfer {
                from: ctx.accounts.revenue_vault.to_account_info(),
                to: ctx.accounts.treasury_vault.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            };
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                signer,
            );
            token::transfer(cpi_ctx, treasury_amount)?;
        }

        // User rebate
        if user_rebate > 0 {
            let cpi_accounts = Transfer {
                from: ctx.accounts.revenue_vault.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            };
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                signer,
            );
            token::transfer(cpi_ctx, user_rebate)?;
        }

        emit!(SwapFinalizedEvent {
            intent_id: intent.key(),
            executor,
            amount_out: actual_amount_out,
            bid_amount,
            lp_share: lp_amount,
            treasury_share: treasury_amount,
            user_rebate,
            timestamp: clock.unix_timestamp,
        });

        msg!(
            "Swap finalized: {} tokens out, {} bid distributed",
            actual_amount_out,
            bid_amount
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Config::LEN,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,

    /// CHECK: Verified externally
    pub lp_rewards_vault: AccountInfo<'info>,

    /// CHECK: Verified externally
    pub treasury_vault: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SubmitIntent<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + Intent::LEN
    )]
    pub intent: Account<'info, Intent>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FinalizeSwap<'info> {
    #[account(mut, constraint = !intent.executed @ ShieldError::AlreadyExecuted)]
    pub intent: Account<'info, Intent>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub executor: Signer<'info>,

    #[account(mut)]
    pub executor_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub revenue_vault: Account<'info, TokenAccount>,

    #[account(mut, address = config.lp_rewards_vault)]
    pub lp_rewards_vault: Account<'info, TokenAccount>,

    #[account(mut, address = config.treasury_vault)]
    pub treasury_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Config {
    pub authority: Pubkey,
    pub lp_share_bps: u16,
    pub treasury_share_bps: u16,
    pub user_rebate_bps: u16,
    pub lp_rewards_vault: Pubkey,
    pub treasury_vault: Pubkey,
    pub bump: u8,
}

impl Config {
    pub const LEN: usize = 32 + 2 + 2 + 2 + 32 + 32 + 1;
}

#[account]
pub struct Intent {
    pub user: Pubkey,
    pub token_in: Pubkey,
    pub token_out: Pubkey,
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub expiry_ts: i64,
    pub executed: bool,
    pub executor: Pubkey,
    pub bid_amount: u64,
    pub bump: u8,
    pub created_at: i64,
}

impl Intent {
    pub const LEN: usize = 32 + 32 + 32 + 8 + 8 + 8 + 1 + 32 + 8 + 1 + 8;
}

#[event]
pub struct SwapIntentEvent {
    pub intent_id: Pubkey,
    pub user: Pubkey,
    pub token_in: Pubkey,
    pub token_out: Pubkey,
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub expiry_ts: i64,
    pub timestamp: i64,
}

#[event]
pub struct SwapFinalizedEvent {
    pub intent_id: Pubkey,
    pub executor: Pubkey,
    pub amount_out: u64,
    pub bid_amount: u64,
    pub lp_share: u64,
    pub treasury_share: u64,
    pub user_rebate: u64,
    pub timestamp: i64,
}

#[error_code]
pub enum ShieldError {
    #[msg("Intent has already been executed")]
    AlreadyExecuted,
    #[msg("Intent has expired")]
    ExpiredIntent,
    #[msg("Invalid amount specified")]
    InvalidAmount,
    #[msg("Slippage tolerance exceeded")]
    SlippageExceeded,
    #[msg("Invalid bid amount")]
    InvalidBidAmount,
    #[msg("Share distribution must sum to 10000 bps (100%)")]
    InvalidShareDistribution,
    #[msg("Unauthorized executor")]
    UnauthorizedExecutor,
}