# Generated by default/object.tt
package Paws::MediaConvert::HopDestination;
  use Moose;
  has Priority => (is => 'ro', isa => 'Int', request_name => 'priority', traits => ['NameInRequest']);
  has Queue => (is => 'ro', isa => 'Str', request_name => 'queue', traits => ['NameInRequest']);
  has WaitMinutes => (is => 'ro', isa => 'Int', request_name => 'waitMinutes', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::MediaConvert::HopDestination

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::MediaConvert::HopDestination object:

  $service_obj->Method(Att1 => { Priority => $value, ..., WaitMinutes => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::MediaConvert::HopDestination object:

  $result = $service_obj->Method(...);
  $result->Att1->Priority

=head1 DESCRIPTION

Optional. Configuration for a destination queue to which the job can
hop once a customer-defined minimum wait time has passed.

=head1 ATTRIBUTES


=head2 Priority => Int

Optional. When you set up a job to use queue hopping, you can specify a
different relative priority for the job in the destination queue. If
you don't specify, the relative priority will remain the same as in the
previous queue.


=head2 Queue => Str

Optional unless the job is submitted on the default queue. When you set
up a job to use queue hopping, you can specify a destination queue.
This queue cannot be the original queue to which the job is submitted.
If the original queue isn't the default queue and you don't specify the
destination queue, the job will move to the default queue.


=head2 WaitMinutes => Int

Required for setting up a job to use queue hopping. Minimum wait time
in minutes until the job can hop to the destination queue. Valid range
is 1 to 1440 minutes, inclusive.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::MediaConvert>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

