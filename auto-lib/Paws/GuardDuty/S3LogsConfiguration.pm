# Generated by default/object.tt
package Paws::GuardDuty::S3LogsConfiguration;
  use Moose;
  has Enable => (is => 'ro', isa => 'Bool', request_name => 'enable', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::GuardDuty::S3LogsConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::GuardDuty::S3LogsConfiguration object:

  $service_obj->Method(Att1 => { Enable => $value, ..., Enable => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::GuardDuty::S3LogsConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->Enable

=head1 DESCRIPTION

Describes whether S3 data event logs will be enabled as a data source.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Enable => Bool

The status of S3 data event logs as a data source.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::GuardDuty>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

