//! Derive macros of `sequencer_storage_actor`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, parse_macro_input};

/// Implements `Writes` for a struct by writing its fields in the order they are declared.
#[proc_macro_derive(Writes)]
pub fn derive_writes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let Data::Struct(data) = &input.data else {
        return Error::new_spanned(&input.ident, "`Writes` can only be derived for structs")
            .to_compile_error()
            .into();
    };
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    let fields = data.fields.members();
    quote! {
        impl #impl_generics ::sequencer_storage_actor::Writes for #name #type_generics #where_clause {
            fn write_to(
                &self,
                staged: &mut ::sequencer_storage_actor::writes::StagedWrites,
            ) -> ::sequencer_storage_actor::Result<()> {
                #(::sequencer_storage_actor::Writes::write_to(&self.#fields, staged)?;)*
                Ok(())
            }
        }
    }
    .into()
}
