#[derive(Debug, Options)]
pub struct CommandOptions {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "be verbose")]
    verbose: bool,
    #[options(help = "overwrites file if exists")]
    overwrite: bool,
    #[options(command)]
    command: Option<Command>,
}

#[derive(Debug, Options)]
pub enum Command {
    #[options(help = "Create new CA and generate certs")]
    New(NewOpts),
    #[options(help = "Create new CA")]
    InitCa(InitOpts),
    #[options(help = "Create new certificates")]
    GenCerts(GenOpts),
}

#[derive(Debug, Options)]
pub struct NewOpts {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "set cluster name")]
    cluster_name: Option<String>,
}

#[derive(Debug, Options)]
pub struct InitOpts {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "target directory")]
    dir: Option<String>,
    #[options(help = "overwrites file if exists")]
    overwrite: bool,
}

#[derive(Debug, Options)]
pub struct GenOpts {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "target directory")]
    dir: Option<String>,
}
