package Paws::Credential::SSO {
  use Moose;
  use Digest::SHA qw/sha1_hex/;
  use Config::AWS qw/read_file/;
  use File::HomeDir;
  use JSON::MaybeXS qw/decode_json/;

  has profile => (is => 'ro', default => sub { $ENV{ AWS_DEFAULT_PROFILE } or 'default' });

  has config_file => (is => 'ro', lazy => 1, default => sub {
    my $self = shift;
    if (defined $ENV{AWS_CONFIG_FILE}){
      return $ENV{AWS_CONFIG_FILE};
    } else {
      return $self->path . '/config';
    }
  });

  has path => (is => 'ro', default => sub {
    return (File::HomeDir->my_home || '') . '/.aws/';
  });

  has _ini_contents => (is => 'ro', isa => 'HashRef', lazy => 1, default => sub {
    my $self = shift;
    my $ini_file = $self->config_file;
    return {} if (not -e $ini_file);
    my $ini = read_file($ini_file);
    return $ini;
  });

  has _profile => (is => 'ro', isa => 'HashRef', lazy => 1, default => sub {
    my $self = shift;
    my $profile = $self->profile;
    return $self->_ini_contents->{ $profile } || {};
  });

  has _cached_sso_credentials_file => (is => 'ro', isa => 'Str', lazy => 1, default => sub {
    my $self = shift;
    my $profile = $self->_profile;

    my $profile_json = JSON::MaybeXS->new->utf8->canonical->encode({
      startUrl  => $profile->{sso_start_url},
      roleName  => $profile->{sso_role_name},
      accountId => $profile->{sso_account_id}
    });

    my $json_sha1 = sha1_hex($profile_json);
    return $self->path . "cli/cache/$json_sha1.json";
  });

  has _cached_credentials => (is => 'ro', isa => 'HashRef', lazy => 1, default => sub {
    my $self = shift;

    my $sso_credentials_file = $self->_cached_sso_credentials_file;

    return {} if (not -e $sso_credentials_file);

    open my $sso_credentials_file_fh, '<:raw', $sso_credentials_file or die "Could not open $sso_credentials_file: $!";
    my $sso_credentials_json = <$sso_credentials_file_fh>;
    close $sso_credentials_file_fh;

    return JSON::MaybeXS->new->utf8->decode($sso_credentials_json)->{Credentials};
  });

  sub access_key {
    my $self = shift;

    return $self->_cached_credentials->{AccessKeyId};
  }

  sub secret_key {
    my $self = shift;

    return $self->_cached_credentials->{SecretAccessKey};
  }

  sub session_token {
    my $self = shift;
    return $self->_cached_credentials->{SessionToken};
  }
}

1;
### main pod documentation begin ###
