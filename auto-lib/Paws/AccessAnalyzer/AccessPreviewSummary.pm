# Generated by default/object.tt
package Paws::AccessAnalyzer::AccessPreviewSummary;
  use Moose;
  has AnalyzerArn => (is => 'ro', isa => 'Str', request_name => 'analyzerArn', traits => ['NameInRequest'], required => 1);
  has CreatedAt => (is => 'ro', isa => 'Str', request_name => 'createdAt', traits => ['NameInRequest'], required => 1);
  has Id => (is => 'ro', isa => 'Str', request_name => 'id', traits => ['NameInRequest'], required => 1);
  has Status => (is => 'ro', isa => 'Str', request_name => 'status', traits => ['NameInRequest'], required => 1);
  has StatusReason => (is => 'ro', isa => 'Paws::AccessAnalyzer::AccessPreviewStatusReason', request_name => 'statusReason', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::AccessAnalyzer::AccessPreviewSummary

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AccessAnalyzer::AccessPreviewSummary object:

  $service_obj->Method(Att1 => { AnalyzerArn => $value, ..., StatusReason => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AccessAnalyzer::AccessPreviewSummary object:

  $result = $service_obj->Method(...);
  $result->Att1->AnalyzerArn

=head1 DESCRIPTION

Contains a summary of information about an access preview.

=head1 ATTRIBUTES


=head2 B<REQUIRED> AnalyzerArn => Str

The ARN of the analyzer used to generate the access preview.


=head2 B<REQUIRED> CreatedAt => Str

The time at which the access preview was created.


=head2 B<REQUIRED> Id => Str

The unique ID for the access preview.


=head2 B<REQUIRED> Status => Str

The status of the access preview.

=over

=item *

C<Creating> - The access preview creation is in progress.

=item *

C<Completed> - The access preview is complete and previews the findings
for external access to the resource.

=item *

C<Failed> - The access preview creation has failed.

=back



=head2 StatusReason => L<Paws::AccessAnalyzer::AccessPreviewStatusReason>





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AccessAnalyzer>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

