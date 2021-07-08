# Generated by default/object.tt
package Paws::WAF::RegexPatternSet;
  use Moose;
  has Name => (is => 'ro', isa => 'Str');
  has RegexPatternSetId => (is => 'ro', isa => 'Str', required => 1);
  has RegexPatternStrings => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::WAF::RegexPatternSet

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::WAF::RegexPatternSet object:

  $service_obj->Method(Att1 => { Name => $value, ..., RegexPatternStrings => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::WAF::RegexPatternSet object:

  $result = $service_obj->Method(...);
  $result->Att1->Name

=head1 DESCRIPTION

This is B<AWS WAF Classic> documentation. For more information, see AWS
WAF Classic
(https://docs.aws.amazon.com/waf/latest/developerguide/classic-waf-chapter.html)
in the developer guide.

B<For the latest version of AWS WAF>, use the AWS WAFV2 API and see the
AWS WAF Developer Guide
(https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html).
With the latest version, AWS WAF has a single set of endpoints for
regional and global use.

The C<RegexPatternSet> specifies the regular expression (regex) pattern
that you want AWS WAF to search for, such as C<B[a@]dB[o0]t>. You can
then configure AWS WAF to reject those requests.

=head1 ATTRIBUTES


=head2 Name => Str

A friendly name or description of the RegexPatternSet. You can't change
C<Name> after you create a C<RegexPatternSet>.


=head2 B<REQUIRED> RegexPatternSetId => Str

The identifier for the C<RegexPatternSet>. You use C<RegexPatternSetId>
to get information about a C<RegexPatternSet>, update a
C<RegexPatternSet>, remove a C<RegexPatternSet> from a
C<RegexMatchSet>, and delete a C<RegexPatternSet> from AWS WAF.

C<RegexMatchSetId> is returned by CreateRegexPatternSet and by
ListRegexPatternSets.


=head2 B<REQUIRED> RegexPatternStrings => ArrayRef[Str|Undef]

Specifies the regular expression (regex) patterns that you want AWS WAF
to search for, such as C<B[a@]dB[o0]t>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::WAF>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

