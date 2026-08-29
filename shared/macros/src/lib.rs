// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use proc_macro::TokenStream;
use proc_macro2::Span;
use syn::{
    Ident, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

use meister_common::attribution::License;

/// Attribution that is present but empty is attribution that says nothing,
/// and the whole point of these attributes being macros rather than comments
/// is that the compiler checks them. Every field is checked for something —
/// this is the check for the ones whose only requirement is content.
fn non_empty(lit: &LitStr, what: &str) -> syn::Result<()> {
    if lit.value().trim().is_empty() {
        return Err(syn::Error::new(
            lit.span(),
            format!("`{what}` must not be empty"),
        ));
    }
    Ok(())
}

fn validate_date(date: &LitStr) -> syn::Result<()> {
    let v = date.value();
    let ok = (v.len() == 7 || v.len() == 10)
        && v.as_bytes().get(4) == Some(&b'-')
        && v[..4].bytes().all(|b| b.is_ascii_digit())
        && v[5..7].bytes().all(|b| b.is_ascii_digit());

    if ok {
        Ok(())
    } else {
        Err(syn::Error::new(
            date.span(),
            "`date` must be in the format \"YYYY-MM\" or \"YYYY-MM-DD\"",
        ))
    }
}

struct SourcedArgs {
    site: LitStr,
    url: LitStr,
    date: LitStr,
    license: Option<Ident>,
    author: Option<LitStr>,
}

impl Parse for SourcedArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let (mut site, mut url, mut date, mut license, mut author) = (None, None, None, None, None);

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            match key.to_string().as_str() {
                "site" => site = Some(input.parse()?),
                "url" => url = Some(input.parse()?),
                "date" => date = Some(input.parse()?),
                "license" => license = Some(input.parse()?),
                "author" => author = Some(input.parse()?),
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unkonw argument `{other}`, expected are: site, url, date, license, author"
                        ),
                    ));
                }
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(SourcedArgs {
            site: site.ok_or_else(|| syn::Error::new(Span::call_site(), "`site` is required"))?,
            url: url.ok_or_else(|| syn::Error::new(Span::call_site(), "`url` is required"))?,
            date: date.ok_or_else(|| syn::Error::new(Span::call_site(), "`date` is required"))?,
            license,
            author,
        })
    }
}

/// A source attribution whose url cannot be opened is not an attribution.
/// Only the scheme is checked — the macro cannot fetch anything, and a
/// stricter shape check would reject perfectly good urls.
fn validate_url(url: &LitStr) -> syn::Result<()> {
    non_empty(url, "url")?;
    let v = url.value();
    if !(v.starts_with("http://") || v.starts_with("https://")) {
        return Err(syn::Error::new(
            url.span(),
            "`url` must start with http:// or https://",
        ));
    }
    Ok(())
}

#[proc_macro_attribute]
pub fn sourced(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as SourcedArgs);

    if let Err(e) = non_empty(&args.site, "site")
        .and_then(|()| validate_url(&args.url))
        .and_then(|()| match &args.author {
            Some(author) => non_empty(author, "author"),
            None => Ok(()),
        })
        .and_then(|()| validate_date(&args.date))
    {
        return e.to_compile_error().into();
    }

    if let Some(license) = &args.license {
        let name = license.to_string();
        if License::parse(&name).is_none() {
            let known: Vec<_> = License::names().collect();
            return syn::Error::new(
                license.span(),
                format!("unknown license `{name}`. Known are: {}", known.join(", ")),
            )
            .to_compile_error()
            .into();
        }
    }
    item
}
