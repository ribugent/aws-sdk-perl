
package Paws::SavingsPlans::DeleteQueuedSavingsPlan;
  use Moose;
  has SavingsPlanId => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'savingsPlanId', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'DeleteQueuedSavingsPlan');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/DeleteQueuedSavingsPlan');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'POST');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::SavingsPlans::DeleteQueuedSavingsPlanResponse');
1;

### main pod documentation begin ###

=head1 NAME

Paws::SavingsPlans::DeleteQueuedSavingsPlan - Arguments for method DeleteQueuedSavingsPlan on L<Paws::SavingsPlans>

=head1 DESCRIPTION

This class represents the parameters used for calling the method DeleteQueuedSavingsPlan on the
L<AWS Savings Plans|Paws::SavingsPlans> service. Use the attributes of this class
as arguments to method DeleteQueuedSavingsPlan.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to DeleteQueuedSavingsPlan.

=head1 SYNOPSIS

    my $savingsplans = Paws->service('SavingsPlans');
    my $DeleteQueuedSavingsPlanResponse =
      $savingsplans->DeleteQueuedSavingsPlan(
      SavingsPlanId => 'MySavingsPlanId',

      );

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/savingsplans/DeleteQueuedSavingsPlan>

=head1 ATTRIBUTES


=head2 B<REQUIRED> SavingsPlanId => Str

The ID of the Savings Plan.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method DeleteQueuedSavingsPlan in L<Paws::SavingsPlans>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

