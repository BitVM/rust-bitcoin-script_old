use super::parse::Syntax;
use bitcoin::blockdata::opcodes::Opcode;
use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, quote_spanned};

pub fn generate(syntax: Vec<(Syntax, Span)>) -> TokenStream {
    let mut tokens = quote!(::bitcoin::blockdata::script::Builder::new());

    for (item, span) in syntax {
        let push = match item {
            Syntax::Opcode(opcode) => generate_opcode(opcode, span),
            Syntax::Bytes(bytes) => generate_bytes(bytes, span),
            Syntax::Int(int) => generate_int(int, span),
            Syntax::Escape(expression) => {
                let builder = tokens;
                tokens = TokenStream::new();
                generate_escape(builder, expression, span)
            }
        };
        tokens.extend(push);
    }

    tokens.extend(quote!(.into_script()));
    tokens
}

fn generate_opcode(opcode: Opcode, span: Span) -> TokenStream {
    let ident = Ident::new(opcode.to_string().as_ref(), span);
    quote_spanned!(span=>
        .push_opcode(
            ::bitcoin::blockdata::opcodes::all::#ident
        )
    )
}

fn generate_bytes(bytes: Vec<u8>, span: Span) -> TokenStream {
    let mut slice = TokenStream::new();
    for byte in bytes {
        slice.extend(quote!(#byte,));
    }
    quote_spanned!(span=>.push_slice(&[#slice]))
}

fn generate_int(n: i64, span: Span) -> TokenStream {
    quote_spanned!(span=>.push_int(#n))
}

fn generate_escape(builder: TokenStream, expression: TokenStream, span: Span) -> TokenStream {
    quote_spanned!(span=>
        (|builder, value| {
            #[allow(clippy::all)]

            use ::bitcoin::blockdata::script::Builder;
            fn push(builder: Builder, value: impl pushable::Pushable) -> Builder {
                value.bitcoin_script_push(builder)
            }
            push(builder, value)
        })(
            #builder,
            #expression
        )
    )
}
