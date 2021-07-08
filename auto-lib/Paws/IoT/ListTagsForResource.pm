
package Paws::IoT::ListTagsForResource;
  use Moose;
  has NextToken => (is => 'ro', isa => 'Str', traits => ['ParamInQuery'], query_name => 'nextToken');
  has ResourceArn => (is => 'ro', isa => 'Str', traits => ['ParamInQuery'], query_name => 'resourceArn', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ListTagsForResource');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/tags');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'GET');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::IoT::ListTagsForResourceResponse');
1;

### main pod documentation begin ###

=head1 NAME

Paws::IoT::ListTagsForResource - Arguments for method ListTagsForResource on L<Paws::IoT>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ListTagsForResource on the
L<AWS IoT|Paws::IoT> service. Use the attributes of this class
as arguments to method ListTagsForResource.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ListTagsForResource.

=head1 SYNOPSIS

    my $iot = Paws->service('IoT');
    my $ListTagsForResourceResponse = $iot->ListTagsForResource(
      ResourceArn => 'MyResourceArn',
      NextToken   => 'MyNextToken',     # OPTIONAL
    );

    # Results:
    my $NextToken = $ListTagsForResourceResponse->NextToken;
    my $Tags      = $ListTagsForResourceResponse->Tags;

    # Returns a L<Paws::IoT::ListTagsForResourceResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/iot/ListTagsForResource>

=head1 ATTRIBUTES


=head2 NextToken => Str

To retrieve the next set of results, the C<nextToken> value from a
previous response; otherwise B<null> to receive the first set of
results.



=head2 B<REQUIRED> ResourceArn => Str

The ARN of the resource.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ListTagsForResource in L<Paws::IoT>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

