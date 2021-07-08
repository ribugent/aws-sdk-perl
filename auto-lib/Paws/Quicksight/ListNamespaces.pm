
package Paws::Quicksight::ListNamespaces;
  use Moose;
  has AwsAccountId => (is => 'ro', isa => 'Str', traits => ['ParamInURI'], uri_name => 'AwsAccountId', required => 1);
  has MaxResults => (is => 'ro', isa => 'Int', traits => ['ParamInQuery'], query_name => 'max-results');
  has NextToken => (is => 'ro', isa => 'Str', traits => ['ParamInQuery'], query_name => 'next-token');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ListNamespaces');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/accounts/{AwsAccountId}/namespaces');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'GET');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::Quicksight::ListNamespacesResponse');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Quicksight::ListNamespaces - Arguments for method ListNamespaces on L<Paws::Quicksight>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ListNamespaces on the
L<Amazon QuickSight|Paws::Quicksight> service. Use the attributes of this class
as arguments to method ListNamespaces.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ListNamespaces.

=head1 SYNOPSIS

    my $quicksight = Paws->service('Quicksight');
    my $ListNamespacesResponse = $quicksight->ListNamespaces(
      AwsAccountId => 'MyAwsAccountId',
      MaxResults   => 1,                  # OPTIONAL
      NextToken    => 'MyString',         # OPTIONAL
    );

    # Results:
    my $Namespaces = $ListNamespacesResponse->Namespaces;
    my $NextToken  = $ListNamespacesResponse->NextToken;
    my $RequestId  = $ListNamespacesResponse->RequestId;
    my $Status     = $ListNamespacesResponse->Status;

    # Returns a L<Paws::Quicksight::ListNamespacesResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/quicksight/ListNamespaces>

=head1 ATTRIBUTES


=head2 B<REQUIRED> AwsAccountId => Str

The ID for the AWS account that contains the QuickSight namespaces that
you want to list.



=head2 MaxResults => Int

The maximum number of results to return.



=head2 NextToken => Str

A pagination token that can be used in a subsequent request.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ListNamespaces in L<Paws::Quicksight>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

