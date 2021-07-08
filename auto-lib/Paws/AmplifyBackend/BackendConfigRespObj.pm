# Generated by default/object.tt
package Paws::AmplifyBackend::BackendConfigRespObj;
  use Moose;
  has AppId => (is => 'ro', isa => 'Str', request_name => 'appId', traits => ['NameInRequest']);
  has BackendManagerAppId => (is => 'ro', isa => 'Str', request_name => 'backendManagerAppId', traits => ['NameInRequest']);
  has Error => (is => 'ro', isa => 'Str', request_name => 'error', traits => ['NameInRequest']);
  has LoginAuthConfig => (is => 'ro', isa => 'Paws::AmplifyBackend::LoginAuthConfigReqObj', request_name => 'loginAuthConfig', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::AmplifyBackend::BackendConfigRespObj

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AmplifyBackend::BackendConfigRespObj object:

  $service_obj->Method(Att1 => { AppId => $value, ..., LoginAuthConfig => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AmplifyBackend::BackendConfigRespObj object:

  $result = $service_obj->Method(...);
  $result->Att1->AppId

=head1 DESCRIPTION

The response object for this operation.

=head1 ATTRIBUTES


=head2 AppId => Str

The app ID.


=head2 BackendManagerAppId => Str

The app ID for the backend manager.


=head2 Error => Str

If the request fails, this error is returned.


=head2 LoginAuthConfig => L<Paws::AmplifyBackend::LoginAuthConfigReqObj>

Describes the Amazon Cognito configurations for the Admin UI auth
resource to log in with.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AmplifyBackend>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

