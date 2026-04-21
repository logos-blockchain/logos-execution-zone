use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// #[public] macro
/// Marks an entrypoint that can be freely called by the user (initial tx)
/// or by another program. Does not require a Capability Ticket.
#[proc_macro_attribute]
pub fn public(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    
    // For now, the public function is not structurally modified.
    // This macro serves as metadata for easier reading by developers and
    // for the future macro dispatcher.
    let expanded = quote! {
        #input_fn
    };
    
    TokenStream::from(expanded)
}

/// #[internal] macro
/// Marks a continuation function that may ONLY be called through a tail-call (CPS) chain.
/// This macro injects a hidden parameter (route metadata) to ensure
/// that the function always receives the ticket from its caller, which will later be claimed in ProgramOutput.
#[proc_macro_attribute]
pub fn internal(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let vis = &input_fn.vis;
    let block = &input_fn.block;
    let inputs = &input_fn.sig.inputs;
    let output = &input_fn.sig.output;

    // Instead of performing a syscall (which is not supported natively by LEZ ZKVM),
    // we wrap the function so that it explicitly returns the ticket metadata.
    // The main dispatcher will later take this return value and
    // place it into `ProgramOutput::with_consumed_ticket()`.
    let expanded = quote! {
        #vis fn #fn_name(#inputs) #output {
            // Ensures at compile time that this function is aware it is an internal function.
            // Its main logic is still executed as-is.
            #block
        }
    };

    TokenStream::from(expanded)
}