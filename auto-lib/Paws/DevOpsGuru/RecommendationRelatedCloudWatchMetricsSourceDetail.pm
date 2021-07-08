# Generated by default/object.tt
package Paws::DevOpsGuru::RecommendationRelatedCloudWatchMetricsSourceDetail;
  use Moose;
  has MetricName => (is => 'ro', isa => 'Str');
  has Namespace => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::DevOpsGuru::RecommendationRelatedCloudWatchMetricsSourceDetail

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DevOpsGuru::RecommendationRelatedCloudWatchMetricsSourceDetail object:

  $service_obj->Method(Att1 => { MetricName => $value, ..., Namespace => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DevOpsGuru::RecommendationRelatedCloudWatchMetricsSourceDetail object:

  $result = $service_obj->Method(...);
  $result->Att1->MetricName

=head1 DESCRIPTION

Information about an Amazon CloudWatch metric that is analyzed by
DevOps Guru. It is one of many analyzed metrics that are used to
generate insights.

=head1 ATTRIBUTES


=head2 MetricName => Str

The name of the CloudWatch metric.


=head2 Namespace => Str

The namespace of the CloudWatch metric. A namespace is a container for
CloudWatch metrics.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DevOpsGuru>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

