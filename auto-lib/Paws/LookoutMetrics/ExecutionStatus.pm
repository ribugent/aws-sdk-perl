# Generated by default/object.tt
package Paws::LookoutMetrics::ExecutionStatus;
  use Moose;
  has FailureReason => (is => 'ro', isa => 'Str');
  has Status => (is => 'ro', isa => 'Str');
  has Timestamp => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::LookoutMetrics::ExecutionStatus

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LookoutMetrics::ExecutionStatus object:

  $service_obj->Method(Att1 => { FailureReason => $value, ..., Timestamp => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LookoutMetrics::ExecutionStatus object:

  $result = $service_obj->Method(...);
  $result->Att1->FailureReason

=head1 DESCRIPTION

The status of an anomaly detector run.

=head1 ATTRIBUTES


=head2 FailureReason => Str

The reason that the run failed, if applicable.


=head2 Status => Str

The run's status.


=head2 Timestamp => Str

The run's timestamp.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LookoutMetrics>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

