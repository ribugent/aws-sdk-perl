
package Paws::CloudWatchEvents::RemoveTargets;
  use Moose;
  has EventBusName => (is => 'ro', isa => 'Str');
  has Force => (is => 'ro', isa => 'Bool');
  has Ids => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);
  has Rule => (is => 'ro', isa => 'Str', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'RemoveTargets');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::CloudWatchEvents::RemoveTargetsResponse');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::CloudWatchEvents::RemoveTargets - Arguments for method RemoveTargets on L<Paws::CloudWatchEvents>

=head1 DESCRIPTION

This class represents the parameters used for calling the method RemoveTargets on the
L<Amazon EventBridge|Paws::CloudWatchEvents> service. Use the attributes of this class
as arguments to method RemoveTargets.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to RemoveTargets.

=head1 SYNOPSIS

    my $events = Paws->service('CloudWatchEvents');
    my $RemoveTargetsResponse = $events->RemoveTargets(
      Ids => [
        'MyTargetId', ...    # min: 1, max: 64
      ],
      Rule         => 'MyRuleName',
      EventBusName => 'MyEventBusNameOrArn',    # OPTIONAL
      Force        => 1,                        # OPTIONAL
    );

    # Results:
    my $FailedEntries    = $RemoveTargetsResponse->FailedEntries;
    my $FailedEntryCount = $RemoveTargetsResponse->FailedEntryCount;

    # Returns a L<Paws::CloudWatchEvents::RemoveTargetsResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/events/RemoveTargets>

=head1 ATTRIBUTES


=head2 EventBusName => Str

The name or ARN of the event bus associated with the rule. If you omit
this, the default event bus is used.



=head2 Force => Bool

If this is a managed rule, created by an AWS service on your behalf,
you must specify C<Force> as C<True> to remove targets. This parameter
is ignored for rules that are not managed rules. You can check whether
a rule is a managed rule by using C<DescribeRule> or C<ListRules> and
checking the C<ManagedBy> field of the response.



=head2 B<REQUIRED> Ids => ArrayRef[Str|Undef]

The IDs of the targets to remove from the rule.



=head2 B<REQUIRED> Rule => Str

The name of the rule.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method RemoveTargets in L<Paws::CloudWatchEvents>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

