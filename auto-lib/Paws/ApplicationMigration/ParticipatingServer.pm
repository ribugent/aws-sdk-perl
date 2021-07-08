# Generated by default/object.tt
package Paws::ApplicationMigration::ParticipatingServer;
  use Moose;
  has LaunchStatus => (is => 'ro', isa => 'Str', request_name => 'launchStatus', traits => ['NameInRequest']);
  has SourceServerID => (is => 'ro', isa => 'Str', request_name => 'sourceServerID', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::ApplicationMigration::ParticipatingServer

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ApplicationMigration::ParticipatingServer object:

  $service_obj->Method(Att1 => { LaunchStatus => $value, ..., SourceServerID => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ApplicationMigration::ParticipatingServer object:

  $result = $service_obj->Method(...);
  $result->Att1->LaunchStatus

=head1 DESCRIPTION

Server participating in Job.

=head1 ATTRIBUTES


=head2 LaunchStatus => Str

Participating server launch status.


=head2 SourceServerID => Str

Participating server Source Server ID.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ApplicationMigration>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

