# Generated by default/object.tt
package Paws::CodeBuild::CodeCoverage;
  use Moose;
  has BranchCoveragePercentage => (is => 'ro', isa => 'Num', request_name => 'branchCoveragePercentage', traits => ['NameInRequest']);
  has BranchesCovered => (is => 'ro', isa => 'Int', request_name => 'branchesCovered', traits => ['NameInRequest']);
  has BranchesMissed => (is => 'ro', isa => 'Int', request_name => 'branchesMissed', traits => ['NameInRequest']);
  has Expired => (is => 'ro', isa => 'Str', request_name => 'expired', traits => ['NameInRequest']);
  has FilePath => (is => 'ro', isa => 'Str', request_name => 'filePath', traits => ['NameInRequest']);
  has Id => (is => 'ro', isa => 'Str', request_name => 'id', traits => ['NameInRequest']);
  has LineCoveragePercentage => (is => 'ro', isa => 'Num', request_name => 'lineCoveragePercentage', traits => ['NameInRequest']);
  has LinesCovered => (is => 'ro', isa => 'Int', request_name => 'linesCovered', traits => ['NameInRequest']);
  has LinesMissed => (is => 'ro', isa => 'Int', request_name => 'linesMissed', traits => ['NameInRequest']);
  has ReportARN => (is => 'ro', isa => 'Str', request_name => 'reportARN', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::CodeBuild::CodeCoverage

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::CodeBuild::CodeCoverage object:

  $service_obj->Method(Att1 => { BranchCoveragePercentage => $value, ..., ReportARN => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::CodeBuild::CodeCoverage object:

  $result = $service_obj->Method(...);
  $result->Att1->BranchCoveragePercentage

=head1 DESCRIPTION

Contains code coverage report information.

Line coverage measures how many statements your tests cover. A
statement is a single instruction, not including comments,
conditionals, etc.

Branch coverage determines if your tests cover every possible branch of
a control structure, such as an C<if> or C<case> statement.

=head1 ATTRIBUTES


=head2 BranchCoveragePercentage => Num

The percentage of branches that are covered by your tests.


=head2 BranchesCovered => Int

The number of conditional branches that are covered by your tests.


=head2 BranchesMissed => Int

The number of conditional branches that are not covered by your tests.


=head2 Expired => Str

The date and time that the tests were run.


=head2 FilePath => Str

The path of the test report file.


=head2 Id => Str

The identifier of the code coverage report.


=head2 LineCoveragePercentage => Num

The percentage of lines that are covered by your tests.


=head2 LinesCovered => Int

The number of lines that are covered by your tests.


=head2 LinesMissed => Int

The number of lines that are not covered by your tests.


=head2 ReportARN => Str

The ARN of the report.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::CodeBuild>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

