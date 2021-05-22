
package Paws::Organizations::ListHandshakesForOrganization;
  use Moose;
  has Filter => (is => 'ro', isa => 'Paws::Organizations::HandshakeFilter');
  has MaxResults => (is => 'ro', isa => 'Int');
  has NextToken => (is => 'ro', isa => 'Str');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ListHandshakesForOrganization');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::Organizations::ListHandshakesForOrganizationResponse');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Organizations::ListHandshakesForOrganization - Arguments for method ListHandshakesForOrganization on L<Paws::Organizations>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ListHandshakesForOrganization on the
L<AWS Organizations|Paws::Organizations> service. Use the attributes of this class
as arguments to method ListHandshakesForOrganization.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ListHandshakesForOrganization.

=head1 SYNOPSIS

    my $organizations = Paws->service('Organizations');
    # To retrieve a list of the handshakes associated with an organization
    # The following example shows you how to get a list of handshakes associated
    # with the current organization:
    my $ListHandshakesForOrganizationResponse =
      $organizations->ListHandshakesForOrganization();

    # Results:
    my $Handshakes = $ListHandshakesForOrganizationResponse->Handshakes;

# Returns a L<Paws::Organizations::ListHandshakesForOrganizationResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/organizations/ListHandshakesForOrganization>

=head1 ATTRIBUTES


=head2 Filter => L<Paws::Organizations::HandshakeFilter>

A filter of the handshakes that you want included in the response. The
default is all types. Use the C<ActionType> element to limit the output
to only a specified type, such as C<INVITE>, C<ENABLE-ALL-FEATURES>, or
C<APPROVE-ALL-FEATURES>. Alternatively, for the C<ENABLE-ALL-FEATURES>
handshake that generates a separate child handshake for each member
account, you can specify the C<ParentHandshakeId> to see only the
handshakes that were generated by that parent request.



=head2 MaxResults => Int

The total number of results that you want included on each page of the
response. If you do not include this parameter, it defaults to a value
that is specific to the operation. If additional items exist beyond the
maximum you specify, the C<NextToken> response element is present and
has a value (is not null). Include that value as the C<NextToken>
request parameter in the next call to the operation to get the next
part of the results. Note that Organizations might return fewer results
than the maximum even when there are more results available. You should
check C<NextToken> after every operation to ensure that you receive all
of the results.



=head2 NextToken => Str

The parameter for receiving additional results if you receive a
C<NextToken> response in a previous request. A C<NextToken> response
indicates that more output is available. Set this parameter to the
value of the previous call's C<NextToken> response to indicate where
the output should continue from.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ListHandshakesForOrganization in L<Paws::Organizations>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

