# Generated by default/object.tt
package Paws::AmplifyBackend::CreateBackendReqObj;
  use Moose;
  has AppId => (is => 'ro', isa => 'Str', request_name => 'appId', traits => ['NameInRequest'], required => 1);
  has AppName => (is => 'ro', isa => 'Str', request_name => 'appName', traits => ['NameInRequest'], required => 1);
  has BackendEnvironmentName => (is => 'ro', isa => 'Str', request_name => 'backendEnvironmentName', traits => ['NameInRequest'], required => 1);
  has ResourceConfig => (is => 'ro', isa => 'Paws::AmplifyBackend::ResourceConfig', request_name => 'resourceConfig', traits => ['NameInRequest']);
  has ResourceName => (is => 'ro', isa => 'Str', request_name => 'resourceName', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::AmplifyBackend::CreateBackendReqObj

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AmplifyBackend::CreateBackendReqObj object:

  $service_obj->Method(Att1 => { AppId => $value, ..., ResourceName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AmplifyBackend::CreateBackendReqObj object:

  $result = $service_obj->Method(...);
  $result->Att1->AppId

=head1 DESCRIPTION

The request object for this operation.

=head1 ATTRIBUTES


=head2 B<REQUIRED> AppId => Str

The app ID.


=head2 B<REQUIRED> AppName => Str

The name of the app.


=head2 B<REQUIRED> BackendEnvironmentName => Str

The name of the backend environment.


=head2 ResourceConfig => L<Paws::AmplifyBackend::ResourceConfig>

The resource configuration for the create backend request.


=head2 ResourceName => Str

The name of the resource.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AmplifyBackend>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

