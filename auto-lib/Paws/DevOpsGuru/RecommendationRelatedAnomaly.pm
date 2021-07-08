# Generated by default/object.tt
package Paws::DevOpsGuru::RecommendationRelatedAnomaly;
  use Moose;
  has Resources => (is => 'ro', isa => 'ArrayRef[Paws::DevOpsGuru::RecommendationRelatedAnomalyResource]');
  has SourceDetails => (is => 'ro', isa => 'ArrayRef[Paws::DevOpsGuru::RecommendationRelatedAnomalySourceDetail]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::DevOpsGuru::RecommendationRelatedAnomaly

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DevOpsGuru::RecommendationRelatedAnomaly object:

  $service_obj->Method(Att1 => { Resources => $value, ..., SourceDetails => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DevOpsGuru::RecommendationRelatedAnomaly object:

  $result = $service_obj->Method(...);
  $result->Att1->Resources

=head1 DESCRIPTION

Information about an anomaly that is related to a recommendation.

=head1 ATTRIBUTES


=head2 Resources => ArrayRef[L<Paws::DevOpsGuru::RecommendationRelatedAnomalyResource>]

An array of objects that represent resources in which DevOps Guru
detected anomalous behavior. Each object contains the name and type of
the resource.


=head2 SourceDetails => ArrayRef[L<Paws::DevOpsGuru::RecommendationRelatedAnomalySourceDetail>]

Information about where the anomalous behavior related the
recommendation was found. For example, details in Amazon CloudWatch
metrics.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DevOpsGuru>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

