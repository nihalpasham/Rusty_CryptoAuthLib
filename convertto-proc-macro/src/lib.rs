#![allow(non_snake_case)]

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
// use syn::parse_macro_input;
use syn::punctuated::{Pair, Punctuated};
use syn::{Expr, Token};

/// proc-macro to define a 'ConvertTo' trait and implement it for [u8;151]
///
/// The method `send_packet` returns a [u8;151]. We use the 'ConvertTo' trait to transform the 151-byte array into a 3 or 4 or 32 or 64-byte array.
/// - Responses that contain a payload are either 4, 32, or 64 bytes in length
/// - Responses that do not contain a payload (or additional data) are 4 bytes in length but we exclude the count (or first) byte.
/// So, we only need to pick the first 3 bytes.
///
/// Purpose: This is just to optimize runtime space requirements. We use a ATCA_CMD_SIZE_MAX (151-byte) array
/// to store all responses from the ATECC device as Rust does not yet support code that is generic over
/// the size of an array type i.e. [Foo; 3] and [Bar; 3] are instances of same generic type [T; 3],
/// but [Foo; 3] and [Foo; 5]  are entirely different types.
#[proc_macro]
pub fn ConvertTo(input: TokenStream) -> TokenStream {
    // println!("{:?}", input);

    // Code Parse Phase
    let tokens = input.clone();
    // Here we use the Turbofish syntax for generic (generic over T and P in this case) structs
    // -    SomeStruct::<T, P>::function (or method)
    // Functions in Rust are types i.e. a function is just a function-typed value.
    let parser = Punctuated::<Expr, Token![,]>::parse_terminated;
    // Bringing Parser into scope automatically implements the trait's methods (of which parse() is one) for a function type.
    // In this case, Parser is implemented for our parser function-type
    // Lastly, we call the parse() method on parser to give us our parsed content. In this case, its
    // a Punctuated type.
    let buff = match parser.parse(tokens) {
        Ok(v) => v,
        Err(_e) => panic!(),
    };
    // println!("{:#?}", buff.first());
    let mut func_names = vec![]; // Vector to hold trait method names
    let mut arr_len = vec![]; // Vector to hold array length values (i.e. integer literals)
    let mut docs = vec![]; // Vector to hold docs for methods.
    for pair in buff.pairs() {
        let expr = match pair {
            Pair::Punctuated(T, _P) => match T {
                Expr::Repeat(Array) => &Array.len,
                _ => panic!(),
            },
            Pair::End(T) => match T {
                Expr::Repeat(Array) => &Array.len,
                _ => panic!(),
            },
        };
        let array_len = match *(expr.clone()) {
            syn::Expr::Lit(ExprLit) => match ExprLit.lit {
                syn::Lit::Int(LitInt) => LitInt.base10_digits().parse::<usize>(), // base10_digits() returns a &str, so parse it to a 'usize'
                _ => panic!(),
            },
            _ => panic!(),
        };
        // println!("{:#?}", array_len);
        let len_int_literal = match array_len {
            Ok(val) => val,
            Err(_e) => panic!(),
        };
        let func_name = ["convert_to_", &len_int_literal.to_string()].join("");
        let ident = syn::Ident::new(&func_name, quote::__private::Span::call_site()); // construct trait `method name` and store it in an Ident struct
        arr_len.push(len_int_literal);
        func_names.push(ident);
        docs.push(format!(
            " Convert [u8; 151] to a [u8;{}]",
            &len_int_literal.to_string()
        ));
    }
    // println!("{:#?}", arr_len);
    // println!("{:#?}", func_names);
    // println!("{:#?}", docs);

    // let array = parse_macro_input!(input as syn::TypeArray);
    // let len = &array.len;

    // Code Generate Phase
    (quote! {
        /// Trait to extract the first 'x' bytes of a `[u8;151]`. In this instance its either 3, 4, 32 or 64 bytes.
        pub trait ConvertTo {
            #(#[doc = #docs]
              fn #func_names(&self) -> [u8; #arr_len];)*

        }
        impl ConvertTo for [u8; 151] {
            #(fn #func_names(&self) -> [u8; #arr_len] {
                let mut rsp_bytes = [0; #arr_len];
                for (idx, val) in self[..#arr_len].iter().enumerate() {
                    rsp_bytes[idx] = *val
                }
            rsp_bytes

         })*
    }
    })
    .into()
}
