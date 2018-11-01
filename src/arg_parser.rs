#[derive(Options)]
pub struct CommandOptions {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "be verbose")]
    pub verbose: bool,
    #[options(help = "overwrites file if exists")]
    pub overwrite: bool,
    #[options(command)]
    pub command: Option<Command>,
}

#[derive(Options)]
pub enum Command {
    #[options(help = "Create new CA and generate certs")]
    New(NewOpts),
    #[options(help = "Create new CA")]
    InitCa(InitOpts),
    #[options(help = "Create new certificates")]
    GenCerts(GenOpts),
}

#[derive(Options)]
pub struct NewOpts {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "set cluster name")]
    pub cluster_name: Option<String>,
}

#[derive(Options)]
pub struct InitOpts {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "target directory")]
    pub dir: Option<String>,
    #[options(help = "overwrites file if exists")]
    pub overwrite: bool,
}

#[derive(Options)]
pub struct GenOpts {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "target directory")]
    pub dir: Option<String>,
}
