
package Paws::AppRunner::DeleteService;
  use Moose;
  has ServiceArn => (is => 'ro', isa => 'Str', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'DeleteService');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::AppRunner::DeleteServiceResponse');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::AppRunner::DeleteService - Arguments for method DeleteService on L<Paws::AppRunner>

=head1 DESCRIPTION

This class represents the parameters used for calling the method DeleteService on the
L<AWS App Runner|Paws::AppRunner> service. Use the attributes of this class
as arguments to method DeleteService.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to DeleteService.

=head1 SYNOPSIS

    my $apprunner = Paws->service('AppRunner');
    my $DeleteServiceResponse = $apprunner->DeleteService(
      ServiceArn => 'MyAppRunnerResourceArn',

    );

    # Results:
    my $OperationId = $DeleteServiceResponse->OperationId;
    my $Service     = $DeleteServiceResponse->Service;

    # Returns a L<Paws::AppRunner::DeleteServiceResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/apprunner/DeleteService>

=head1 ATTRIBUTES


=head2 B<REQUIRED> ServiceArn => Str

The Amazon Resource Name (ARN) of the App Runner service that you want
to delete.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method DeleteService in L<Paws::AppRunner>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

