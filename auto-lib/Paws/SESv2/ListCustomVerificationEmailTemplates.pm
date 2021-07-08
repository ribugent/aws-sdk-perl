
package Paws::SESv2::ListCustomVerificationEmailTemplates;
  use Moose;
  has NextToken => (is => 'ro', isa => 'Str', traits => ['ParamInQuery'], query_name => 'NextToken');
  has PageSize => (is => 'ro', isa => 'Int', traits => ['ParamInQuery'], query_name => 'PageSize');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ListCustomVerificationEmailTemplates');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/v2/email/custom-verification-email-templates');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'GET');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::SESv2::ListCustomVerificationEmailTemplatesResponse');
1;

### main pod documentation begin ###

=head1 NAME

Paws::SESv2::ListCustomVerificationEmailTemplates - Arguments for method ListCustomVerificationEmailTemplates on L<Paws::SESv2>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ListCustomVerificationEmailTemplates on the
L<Amazon Simple Email Service|Paws::SESv2> service. Use the attributes of this class
as arguments to method ListCustomVerificationEmailTemplates.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ListCustomVerificationEmailTemplates.

=head1 SYNOPSIS

    my $email = Paws->service('SESv2');
    my $ListCustomVerificationEmailTemplatesResponse =
      $email->ListCustomVerificationEmailTemplates(
      NextToken => 'MyNextToken',    # OPTIONAL
      PageSize  => 1,                # OPTIONAL
      );

    # Results:
    my $CustomVerificationEmailTemplates =
      $ListCustomVerificationEmailTemplatesResponse
      ->CustomVerificationEmailTemplates;
    my $NextToken = $ListCustomVerificationEmailTemplatesResponse->NextToken;

# Returns a L<Paws::SESv2::ListCustomVerificationEmailTemplatesResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/email/ListCustomVerificationEmailTemplates>

=head1 ATTRIBUTES


=head2 NextToken => Str

A token returned from a previous call to
C<ListCustomVerificationEmailTemplates> to indicate the position in the
list of custom verification email templates.



=head2 PageSize => Int

The number of results to show in a single call to
C<ListCustomVerificationEmailTemplates>. If the number of results is
larger than the number you specified in this parameter, then the
response includes a C<NextToken> element, which you can use to obtain
additional results.

The value you specify has to be at least 1, and can be no more than 50.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ListCustomVerificationEmailTemplates in L<Paws::SESv2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

