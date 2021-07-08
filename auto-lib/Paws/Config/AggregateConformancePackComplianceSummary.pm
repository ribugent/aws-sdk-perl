# Generated by default/object.tt
package Paws::Config::AggregateConformancePackComplianceSummary;
  use Moose;
  has ComplianceSummary => (is => 'ro', isa => 'Paws::Config::AggregateConformancePackComplianceCount');
  has GroupName => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Config::AggregateConformancePackComplianceSummary

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Config::AggregateConformancePackComplianceSummary object:

  $service_obj->Method(Att1 => { ComplianceSummary => $value, ..., GroupName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Config::AggregateConformancePackComplianceSummary object:

  $result = $service_obj->Method(...);
  $result->Att1->ComplianceSummary

=head1 DESCRIPTION

Provides a summary of compliance based on either account ID or region.

=head1 ATTRIBUTES


=head2 ComplianceSummary => L<Paws::Config::AggregateConformancePackComplianceCount>

Returns an C<AggregateConformancePackComplianceCount> object.


=head2 GroupName => Str

Groups the result based on AWS Account ID or AWS Region.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Config>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

