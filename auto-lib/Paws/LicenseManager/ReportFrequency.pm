# Generated by default/object.tt
package Paws::LicenseManager::ReportFrequency;
  use Moose;
  has Period => (is => 'ro', isa => 'Str', request_name => 'period', traits => ['NameInRequest']);
  has Value => (is => 'ro', isa => 'Int', request_name => 'value', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LicenseManager::ReportFrequency

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LicenseManager::ReportFrequency object:

  $service_obj->Method(Att1 => { Period => $value, ..., Value => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LicenseManager::ReportFrequency object:

  $result = $service_obj->Method(...);
  $result->Att1->Period

=head1 DESCRIPTION

Details on how frequently reports are generated.

=head1 ATTRIBUTES


=head2 Period => Str

Time period between each report. The period can be daily, weekly, or
monthly.


=head2 Value => Int

Number of times within the frequency period that a report will be
generated. Currently only C<1> is supported.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LicenseManager>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

