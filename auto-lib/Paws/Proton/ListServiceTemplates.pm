
package Paws::Proton::ListServiceTemplates;
  use Moose;
  has MaxResults => (is => 'ro', isa => 'Int', traits => ['NameInRequest'], request_name => 'maxResults' );
  has NextToken => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'nextToken' );

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ListServiceTemplates');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::Proton::ListServiceTemplatesOutput');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Proton::ListServiceTemplates - Arguments for method ListServiceTemplates on L<Paws::Proton>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ListServiceTemplates on the
L<AWS Proton|Paws::Proton> service. Use the attributes of this class
as arguments to method ListServiceTemplates.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ListServiceTemplates.

=head1 SYNOPSIS

    my $proton = Paws->service('Proton');
    my $ListServiceTemplatesOutput = $proton->ListServiceTemplates(
      MaxResults => 1,                # OPTIONAL
      NextToken  => 'MyNextToken',    # OPTIONAL
    );

    # Results:
    my $NextToken = $ListServiceTemplatesOutput->NextToken;
    my $Templates = $ListServiceTemplatesOutput->Templates;

    # Returns a L<Paws::Proton::ListServiceTemplatesOutput> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/proton/ListServiceTemplates>

=head1 ATTRIBUTES


=head2 MaxResults => Int

The maximum number of service templates to list.



=head2 NextToken => Str

A token to indicate the location of the next service template in the
array of service templates, after the list of service templates
previously requested.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ListServiceTemplates in L<Paws::Proton>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

