
package Paws::Kafka::GetCompatibleKafkaVersions;
  use Moose;
  has ClusterArn => (is => 'ro', isa => 'Str', traits => ['ParamInQuery'], query_name => 'clusterArn');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'GetCompatibleKafkaVersions');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/v1/compatible-kafka-versions');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'GET');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::Kafka::GetCompatibleKafkaVersionsResponse');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Kafka::GetCompatibleKafkaVersions - Arguments for method GetCompatibleKafkaVersions on L<Paws::Kafka>

=head1 DESCRIPTION

This class represents the parameters used for calling the method GetCompatibleKafkaVersions on the
L<Managed Streaming for Kafka|Paws::Kafka> service. Use the attributes of this class
as arguments to method GetCompatibleKafkaVersions.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to GetCompatibleKafkaVersions.

=head1 SYNOPSIS

    my $kafka = Paws->service('Kafka');
    my $GetCompatibleKafkaVersionsResponse = $kafka->GetCompatibleKafkaVersions(
      ClusterArn => 'My__string',    # OPTIONAL
    );

    # Results:
    my $CompatibleKafkaVersions =
      $GetCompatibleKafkaVersionsResponse->CompatibleKafkaVersions;

    # Returns a L<Paws::Kafka::GetCompatibleKafkaVersionsResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/kafka/GetCompatibleKafkaVersions>

=head1 ATTRIBUTES


=head2 ClusterArn => Str

The Amazon Resource Name (ARN) of the cluster check.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method GetCompatibleKafkaVersions in L<Paws::Kafka>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

