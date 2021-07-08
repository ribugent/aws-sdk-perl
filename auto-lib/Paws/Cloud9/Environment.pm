# Generated by default/object.tt
package Paws::Cloud9::Environment;
  use Moose;
  has Arn => (is => 'ro', isa => 'Str', request_name => 'arn', traits => ['NameInRequest'], required => 1);
  has ConnectionType => (is => 'ro', isa => 'Str', request_name => 'connectionType', traits => ['NameInRequest']);
  has Description => (is => 'ro', isa => 'Str', request_name => 'description', traits => ['NameInRequest']);
  has Id => (is => 'ro', isa => 'Str', request_name => 'id', traits => ['NameInRequest']);
  has Lifecycle => (is => 'ro', isa => 'Paws::Cloud9::EnvironmentLifecycle', request_name => 'lifecycle', traits => ['NameInRequest']);
  has ManagedCredentialsStatus => (is => 'ro', isa => 'Str', request_name => 'managedCredentialsStatus', traits => ['NameInRequest']);
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest']);
  has OwnerArn => (is => 'ro', isa => 'Str', request_name => 'ownerArn', traits => ['NameInRequest'], required => 1);
  has Type => (is => 'ro', isa => 'Str', request_name => 'type', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Cloud9::Environment

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Cloud9::Environment object:

  $service_obj->Method(Att1 => { Arn => $value, ..., Type => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Cloud9::Environment object:

  $result = $service_obj->Method(...);
  $result->Att1->Arn

=head1 DESCRIPTION

Information about an Cloud9 development environment.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Arn => Str

The Amazon Resource Name (ARN) of the environment.


=head2 ConnectionType => Str

The connection type used for connecting to an Amazon EC2 environment.
C<CONNECT_SSH> is selected by default.


=head2 Description => Str

The description for the environment.


=head2 Id => Str

The ID of the environment.


=head2 Lifecycle => L<Paws::Cloud9::EnvironmentLifecycle>

The state of the environment in its creation or deletion lifecycle.


=head2 ManagedCredentialsStatus => Str

Describes the status of Amazon Web Services managed temporary
credentials for the Cloud9 environment. Available values are:

=over

=item *

C<ENABLED_ON_CREATE>

=item *

C<ENABLED_BY_OWNER>

=item *

C<DISABLED_BY_DEFAULT>

=item *

C<DISABLED_BY_OWNER>

=item *

C<DISABLED_BY_COLLABORATOR>

=item *

C<PENDING_REMOVAL_BY_COLLABORATOR>

=item *

C<PENDING_REMOVAL_BY_OWNER>

=item *

C<FAILED_REMOVAL_BY_COLLABORATOR>

=item *

C<ENABLED_BY_OWNER>

=item *

C<DISABLED_BY_DEFAULT>

=back



=head2 Name => Str

The name of the environment.


=head2 B<REQUIRED> OwnerArn => Str

The Amazon Resource Name (ARN) of the environment owner.


=head2 B<REQUIRED> Type => Str

The type of environment. Valid values include the following:

=over

=item *

C<ec2>: An Amazon Elastic Compute Cloud (Amazon EC2) instance connects
to the environment.

=item *

C<ssh>: Your own server connects to the environment.

=back




=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Cloud9>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

