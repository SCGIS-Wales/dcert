//! One serialiser from tool parameters to `dcert` arguments.
//!
//! Every parameter type that reaches the CLI implements [`ToCliArgs`] and
//! writes itself through an [`ArgBuilder`]. The builder always emits the
//! `--flag=value` form, so a value that starts with `-` can never be read as
//! another flag, and it keeps secrets apart: they go to the environment of
//! the child, never to argv, which every local user can read.

use std::fmt::Display;

/// The argv and environment of one `dcert` run.
#[derive(Debug, Default)]
pub(crate) struct ArgBuilder<'a> {
    args: Vec<String>,
    env: Vec<(&'static str, &'a str)>,
}

impl<'a> ArgBuilder<'a> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `--name` when `on`.
    pub(crate) fn flag(&mut self, name: &str, on: bool) -> &mut Self {
        if on {
            self.args.push(format!("--{name}"));
        }
        self
    }

    /// `--name=value` when there is a value.
    pub(crate) fn value(&mut self, name: &str, value: Option<impl Display>) -> &mut Self {
        if let Some(v) = value {
            self.args.push(format!("--{name}={v}"));
        }
        self
    }

    /// `--name=value` once per value.
    pub(crate) fn repeat<T: Display>(&mut self, name: &str, values: impl IntoIterator<Item = T>) -> &mut Self {
        for v in values {
            self.args.push(format!("--{name}={v}"));
        }
        self
    }

    /// Bare arguments: subcommand names, or positional values the caller
    /// has validated (canonical absolute paths, checked KV paths), which
    /// therefore cannot start with `-`.
    pub(crate) fn positional<T: Display>(&mut self, values: impl IntoIterator<Item = T>) -> &mut Self {
        self.args.extend(values.into_iter().map(|v| v.to_string()));
        self
    }

    /// A secret or credential carrying setting, passed as the environment
    /// variable the CLI reads for it.
    pub(crate) fn env(&mut self, var: &'static str, value: Option<&'a str>) -> &mut Self {
        if let Some(v) = value {
            self.env.push((var, v));
        }
        self
    }

    /// Append another parameter group.
    pub(crate) fn extend(&mut self, group: &'a impl ToCliArgs) -> &mut Self {
        group.write_args(self);
        self
    }

    pub(crate) fn into_parts(self) -> (Vec<String>, Vec<(&'static str, &'a str)>) {
        (self.args, self.env)
    }
}

/// A parameter type that maps onto `dcert` command line flags.
pub(crate) trait ToCliArgs {
    fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>);

    /// The argv and environment these parameters produce.
    fn cli_args(&self) -> (Vec<String>, Vec<(&'static str, &str)>) {
        let mut out = ArgBuilder::new();
        self.write_args(&mut out);
        out.into_parts()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sample {
        on: bool,
        name: Option<String>,
        many: Vec<u16>,
        secret: Option<String>,
    }

    impl ToCliArgs for Sample {
        fn write_args<'a>(&'a self, out: &mut ArgBuilder<'a>) {
            out.flag("on", self.on)
                .value("name", self.name.as_deref())
                .repeat("port", &self.many)
                .env("SAMPLE_SECRET", self.secret.as_deref());
        }
    }

    #[test]
    fn values_use_the_equals_form_and_secrets_stay_out_of_argv() {
        let sample = Sample {
            on: true,
            name: Some("-x".to_string()),
            many: vec![1, 2],
            secret: Some("hunter2".to_string()),
        };
        let (args, env) = sample.cli_args();
        assert_eq!(args, ["--on", "--name=-x", "--port=1", "--port=2"]);
        assert_eq!(env, [("SAMPLE_SECRET", "hunter2")]);
    }

    #[test]
    fn absent_values_emit_nothing() {
        let sample = Sample {
            on: false,
            name: None,
            many: Vec::new(),
            secret: None,
        };
        let (args, env) = sample.cli_args();
        assert!(args.is_empty() && env.is_empty());
    }
}
