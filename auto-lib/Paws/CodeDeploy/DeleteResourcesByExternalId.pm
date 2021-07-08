
package Paws::CodeDeploy::DeleteResourcesByExternalId;
  use Moose;
  has ExternalId => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'externalId' );

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'DeleteResourcesByExternalId');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::CodeDeploy::DeleteResourcesByExternalIdOutput');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::CodeDeploy::DeleteResourcesByExternalId - Arguments for method DeleteResourcesByExternalId on L<Paws::CodeDeploy>

=head1 DESCRIPTION

This class represents the parameters used for calling the method DeleteResourcesByExternalId on the
L<AWS CodeDeploy|Paws::CodeDeploy> service. Use the attributes of this class
as arguments to method DeleteResourcesByExternalId.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to DeleteResourcesByExternalId.

=head1 SYNOPSIS

    my $codedeploy = Paws->service('CodeDeploy');
    my $DeleteResourcesByExternalIdOutput =
      $codedeploy->DeleteResourcesByExternalId(
      ExternalId => 'MyExternalId',    # OPTIONAL
      );

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/codedeploy/DeleteResourcesByExternalId>

=head1 ATTRIBUTES


=head2 ExternalId => Str

The unique ID of an external resource (for example, a CloudFormation
stack ID) that is linked to one or more CodeDeploy resources.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method DeleteResourcesByExternalId in L<Paws::CodeDeploy>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

