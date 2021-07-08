# Generated by default/object.tt
package Paws::ApplicationMigration::LifeCycle;
  use Moose;
  has AddedToServiceDateTime => (is => 'ro', isa => 'Str', request_name => 'addedToServiceDateTime', traits => ['NameInRequest']);
  has ElapsedReplicationDuration => (is => 'ro', isa => 'Str', request_name => 'elapsedReplicationDuration', traits => ['NameInRequest']);
  has FirstByteDateTime => (is => 'ro', isa => 'Str', request_name => 'firstByteDateTime', traits => ['NameInRequest']);
  has LastCutover => (is => 'ro', isa => 'Paws::ApplicationMigration::LifeCycleLastCutover', request_name => 'lastCutover', traits => ['NameInRequest']);
  has LastSeenByServiceDateTime => (is => 'ro', isa => 'Str', request_name => 'lastSeenByServiceDateTime', traits => ['NameInRequest']);
  has LastTest => (is => 'ro', isa => 'Paws::ApplicationMigration::LifeCycleLastTest', request_name => 'lastTest', traits => ['NameInRequest']);
  has State => (is => 'ro', isa => 'Str', request_name => 'state', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::ApplicationMigration::LifeCycle

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ApplicationMigration::LifeCycle object:

  $service_obj->Method(Att1 => { AddedToServiceDateTime => $value, ..., State => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ApplicationMigration::LifeCycle object:

  $result = $service_obj->Method(...);
  $result->Att1->AddedToServiceDateTime

=head1 DESCRIPTION

Lifecycle.

=head1 ATTRIBUTES


=head2 AddedToServiceDateTime => Str

Lifecycle added to service data and time.


=head2 ElapsedReplicationDuration => Str

Lifecycle elapsed time and duration.


=head2 FirstByteDateTime => Str

Lifecycle replication initiation date and time.


=head2 LastCutover => L<Paws::ApplicationMigration::LifeCycleLastCutover>

Lifecycle last Cutover.


=head2 LastSeenByServiceDateTime => Str

Lifecycle last seen date and time.


=head2 LastTest => L<Paws::ApplicationMigration::LifeCycleLastTest>

Lifecycle last Test.


=head2 State => Str

Lifecycle state.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ApplicationMigration>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

