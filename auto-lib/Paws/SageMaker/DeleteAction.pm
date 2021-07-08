
package Paws::SageMaker::DeleteAction;
  use Moose;
  has ActionName => (is => 'ro', isa => 'Str', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'DeleteAction');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::SageMaker::DeleteActionResponse');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::SageMaker::DeleteAction - Arguments for method DeleteAction on L<Paws::SageMaker>

=head1 DESCRIPTION

This class represents the parameters used for calling the method DeleteAction on the
L<Amazon SageMaker Service|Paws::SageMaker> service. Use the attributes of this class
as arguments to method DeleteAction.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to DeleteAction.

=head1 SYNOPSIS

    my $api.sagemaker = Paws->service('SageMaker');
    my $DeleteActionResponse = $api . sagemaker->DeleteAction(
      ActionName => 'MyExperimentEntityName',

    );

    # Results:
    my $ActionArn = $DeleteActionResponse->ActionArn;

    # Returns a L<Paws::SageMaker::DeleteActionResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/api.sagemaker/DeleteAction>

=head1 ATTRIBUTES


=head2 B<REQUIRED> ActionName => Str

The name of the action to delete.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method DeleteAction in L<Paws::SageMaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

