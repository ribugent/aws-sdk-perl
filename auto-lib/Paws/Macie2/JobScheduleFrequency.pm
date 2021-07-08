# Generated by default/object.tt
package Paws::Macie2::JobScheduleFrequency;
  use Moose;
  has DailySchedule => (is => 'ro', isa => 'Paws::Macie2::DailySchedule', request_name => 'dailySchedule', traits => ['NameInRequest']);
  has MonthlySchedule => (is => 'ro', isa => 'Paws::Macie2::MonthlySchedule', request_name => 'monthlySchedule', traits => ['NameInRequest']);
  has WeeklySchedule => (is => 'ro', isa => 'Paws::Macie2::WeeklySchedule', request_name => 'weeklySchedule', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Macie2::JobScheduleFrequency

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Macie2::JobScheduleFrequency object:

  $service_obj->Method(Att1 => { DailySchedule => $value, ..., WeeklySchedule => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Macie2::JobScheduleFrequency object:

  $result = $service_obj->Method(...);
  $result->Att1->DailySchedule

=head1 DESCRIPTION

Specifies the recurrence pattern for running a classification job.

=head1 ATTRIBUTES


=head2 DailySchedule => L<Paws::Macie2::DailySchedule>

Specifies a daily recurrence pattern for running the job.


=head2 MonthlySchedule => L<Paws::Macie2::MonthlySchedule>

Specifies a monthly recurrence pattern for running the job.


=head2 WeeklySchedule => L<Paws::Macie2::WeeklySchedule>

Specifies a weekly recurrence pattern for running the job.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Macie2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

