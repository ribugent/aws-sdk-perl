# Generated by default/object.tt
package Paws::Appflow::SlackConnectorProfileCredentials;
  use Moose;
  has AccessToken => (is => 'ro', isa => 'Str', request_name => 'accessToken', traits => ['NameInRequest']);
  has ClientId => (is => 'ro', isa => 'Str', request_name => 'clientId', traits => ['NameInRequest'], required => 1);
  has ClientSecret => (is => 'ro', isa => 'Str', request_name => 'clientSecret', traits => ['NameInRequest'], required => 1);
  has OAuthRequest => (is => 'ro', isa => 'Paws::Appflow::ConnectorOAuthRequest', request_name => 'oAuthRequest', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Appflow::SlackConnectorProfileCredentials

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Appflow::SlackConnectorProfileCredentials object:

  $service_obj->Method(Att1 => { AccessToken => $value, ..., OAuthRequest => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Appflow::SlackConnectorProfileCredentials object:

  $result = $service_obj->Method(...);
  $result->Att1->AccessToken

=head1 DESCRIPTION

The connector-specific profile credentials required when using Slack.

=head1 ATTRIBUTES


=head2 AccessToken => Str

The credentials used to access protected Slack resources.


=head2 B<REQUIRED> ClientId => Str

The identifier for the client.


=head2 B<REQUIRED> ClientSecret => Str

The client secret used by the OAuth client to authenticate to the
authorization server.


=head2 OAuthRequest => L<Paws::Appflow::ConnectorOAuthRequest>

The OAuth requirement needed to request security tokens from the
connector endpoint.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Appflow>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

