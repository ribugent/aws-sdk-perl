
package Paws::AccessAnalyzer::ApplyArchiveRule;
  use Moose;
  has AnalyzerArn => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'analyzerArn', required => 1);
  has ClientToken => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'clientToken');
  has RuleName => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'ruleName', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ApplyArchiveRule');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/archive-rule');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'PUT');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::API::Response');
1;

### main pod documentation begin ###

=head1 NAME

Paws::AccessAnalyzer::ApplyArchiveRule - Arguments for method ApplyArchiveRule on L<Paws::AccessAnalyzer>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ApplyArchiveRule on the
L<Access Analyzer|Paws::AccessAnalyzer> service. Use the attributes of this class
as arguments to method ApplyArchiveRule.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ApplyArchiveRule.

=head1 SYNOPSIS

    my $access-analyzer = Paws->service('AccessAnalyzer');
    $access -analyzer->ApplyArchiveRule(
      AnalyzerArn => 'MyAnalyzerArn',
      RuleName    => 'MyName',
      ClientToken => 'MyString',        # OPTIONAL
    );

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/access-analyzer/ApplyArchiveRule>

=head1 ATTRIBUTES


=head2 B<REQUIRED> AnalyzerArn => Str

The Amazon resource name (ARN) of the analyzer.



=head2 ClientToken => Str

A client token.



=head2 B<REQUIRED> RuleName => Str

The name of the rule to apply.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ApplyArchiveRule in L<Paws::AccessAnalyzer>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

